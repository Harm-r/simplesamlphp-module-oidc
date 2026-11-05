<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Factories\OAuth2Factory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws\ParsedJws;
use SimpleSAML\Test\Module\oidc\unit\SigningKeyTestTrait;

#[CoversClass(ModuleConfig::class)]
#[CoversClass(IdTokenBuilder::class)]
#[CoversClass(AccessTokenEntity::class)]
#[CoversClass(JwksController::class)]
class MlDsaKeySelectionTest extends TestCase
{
    use SigningKeyTestTrait;


    public static function algorithmProvider(): array
    {
        return [
            'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44],
            'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65],
            'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87],
        ];
    }


    private function config(array $entries): ModuleConfig
    {
        return new ModuleConfig(overrides: [
            ModuleConfig::OPTION_ISSUER => 'https://op.example.org',
            ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => $entries,
        ]);
    }


    private function publishedKeys(ModuleConfig $config): array
    {
        $controller = new JwksController(
            $config,
            new Jwks($config->getSupportedAlgorithms(includeMlDsa: true)),
            new Routes($config, new SspBridge()),
        );
        $response = $controller();
        $this->assertSame(200, $response->getStatusCode());

        return json_decode($response->getContent(), true, 512, JSON_THROW_ON_ERROR);
    }


    private function mint(ModuleConfig $config, ?SignatureAlgorithmEnum $requested = null): array
    {
        $logger = new LoggerService();
        $core = (new CoreFactory($config, $logger))->build();
        $oauth2 = (new OAuth2Factory($config))->build();
        $now = new DateTimeImmutable();
        $client = new ClientEntity(
            'client123',
            '',
            'Client',
            '',
            [],
            ['openid'],
            true,
            extraMetadata: $requested === null ? null : ['id_token_signed_response_alg' => $requested->value],
        );
        $user = new UserEntity('user123', $now, $now, ['uid' => ['subject123']]);
        $access = new AccessTokenEntity(
            bin2hex(random_bytes(8)),
            $client,
            [new ScopeEntity('openid')],
            new DateTimeImmutable('+10 minutes'),
            $oauth2,
            $config,
            'user123',
            subject: 'subject123',
        );
        $extractor = new ClaimTranslatorExtractor(['uid'], new ClaimSetEntityFactory());
        $builder = new IdTokenBuilder($extractor, $core, $config, new SubjectResolver($extractor, $logger));
        $id = $builder->buildFor($user, $access, false, true, null, null, null, null);

        return [
            'access' => $oauth2->jwtAccessTokenFactory()->fromToken($access->toString()),
            'id' => $core->idTokenFactory()->fromToken($id->getToken()),
        ];
    }


    private function assertSelection(
        array $tokens,
        array $jwks,
        SignatureAlgorithmEnum $accessAlgorithm,
        string $accessKid,
        SignatureAlgorithmEnum $idAlgorithm,
        string $idKid,
    ): void {
        foreach ($tokens as $token) {
            $token->verifyWithKeySet($jwks);
        }
        $this->assertSame($accessAlgorithm->value, $tokens['access']->getHeaderClaim('alg'));
        $this->assertSame($accessKid, $tokens['access']->getKeyId());
        $this->assertSame($idAlgorithm->value, $tokens['id']->getHeaderClaim('alg'));
        $this->assertSame($idKid, $tokens['id']->getKeyId());
    }


    #[DataProvider('algorithmProvider')]
    public function testSelectsRequestedAlgorithmFromMixedConfiguredKeys(SignatureAlgorithmEnum $algorithm): void
    {
        $ml = $this->keyEntry($algorithm, 'ml');
        $rsa = $this->keyEntry(SignatureAlgorithmEnum::RS256, 'rsa');
        $ec = $this->keyEntry(SignatureAlgorithmEnum::ES256, 'ec');
        $config = $this->config([$rsa, $ec, $ml]);
        $jwks = $this->publishedKeys($config);

        $this->assertSelection(
            $this->mint($config),
            $jwks,
            SignatureAlgorithmEnum::RS256,
            'rsa',
            SignatureAlgorithmEnum::RS256,
            'rsa',
        );
        $this->assertSelection(
            $this->mint($config, $algorithm),
            $jwks,
            SignatureAlgorithmEnum::RS256,
            'rsa',
            $algorithm,
            'ml',
        );
        $this->assertSelection(
            $this->mint($config, SignatureAlgorithmEnum::ES256),
            $jwks,
            SignatureAlgorithmEnum::RS256,
            'rsa',
            SignatureAlgorithmEnum::ES256,
            'ec',
        );
    }


    #[DataProvider('algorithmProvider')]
    public function testFirstConfiguredKeyControlsDefaultSigning(SignatureAlgorithmEnum $algorithm): void
    {
        $entries = [
            $this->keyEntry($algorithm, 'ml'),
            $this->keyEntry(SignatureAlgorithmEnum::RS256, 'rsa'),
            $this->keyEntry(SignatureAlgorithmEnum::ES256, 'ec'),
        ];
        foreach ([0, 1, 2] as $first) {
            $ordered = $entries;
            $active = array_splice($ordered, $first, 1)[0];
            array_unshift($ordered, $active);
            $config = $this->config($ordered);
            $jwks = $this->publishedKeys($config);
            // Configuration order is local signing policy; JWKS order is not a preference list.
            $jwks['keys'] = array_reverse($jwks['keys']);
            $this->assertSelection(
                $this->mint($config),
                $jwks,
                $active[ModuleConfig::KEY_ALGORITHM],
                $active[ModuleConfig::KEY_KEY_ID],
                $active[ModuleConfig::KEY_ALGORITHM],
                $active[ModuleConfig::KEY_KEY_ID],
            );
        }
    }


    #[DataProvider('algorithmProvider')]
    public function testRotatesMlDsaKeyWhileRetainingOldVerificationKey(SignatureAlgorithmEnum $algorithm): void
    {
        $old = $this->keyEntry($algorithm, 'old');
        $new = $this->keyEntry($algorithm, 'new');
        $rsa = $this->keyEntry(SignatureAlgorithmEnum::RS256, 'rsa');
        $ec = $this->keyEntry(SignatureAlgorithmEnum::ES256, 'ec');
        $before = $this->config([$old, $rsa, $ec]);
        $oldTokens = $this->mint($before);
        $this->assertSelection($oldTokens, $this->publishedKeys($before), $algorithm, 'old', $algorithm, 'old');

        // A new configuration instance represents a subsequent request after manual rollover.
        $after = $this->config([$new, $rsa, $ec, $old]);
        $jwks = $this->publishedKeys($after);
        $this->assertSame(['new', 'rsa', 'ec', 'old'], array_column($jwks['keys'], 'kid'));
        $newTokens = $this->mint($after);
        $this->assertSelection($newTokens, $jwks, $algorithm, 'new', $algorithm, 'new');
        $this->assertSelection($this->mint($after, $algorithm), $jwks, $algorithm, 'new', $algorithm, 'new');
        $this->assertSelection($oldTokens, $jwks, $algorithm, 'old', $algorithm, 'old');

        $withdrawn = $this->publishedKeys($this->config([$new, $rsa, $ec]));
        $this->assertNotContains('old', array_column($withdrawn['keys'], 'kid'));
        $this->assertSelection($newTokens, $withdrawn, $algorithm, 'new', $algorithm, 'new');
        foreach ($oldTokens as $token) {
            $this->assertKeyWasWithdrawn($token, $withdrawn);
        }
    }


    private function assertKeyWasWithdrawn(ParsedJws $token, array $jwks): void
    {
        try {
            $token->verifyWithKeySet($jwks);
            $this->fail('A token signed with a withdrawn key was accepted.');
        } catch (JwsException) {
            $this->addToAssertionCount(1);
        }
    }


    #[DataProvider('algorithmProvider')]
    public function testDoesNotFallBackWhenRequestedAlgorithmHasNoConfiguredKey(SignatureAlgorithmEnum $algorithm): void
    {
        $ml = $this->keyEntry($algorithm, 'ml');
        $config = $this->config([$this->keyEntry(SignatureAlgorithmEnum::RS256, 'rsa'), $ml]);
        $missing = $algorithm === SignatureAlgorithmEnum::MLDSA44
        ? SignatureAlgorithmEnum::MLDSA65
        : SignatureAlgorithmEnum::MLDSA44;

        $this->expectException(OpenIdException::class);
        $this->expectExceptionMessage('Signature key pair for algorithm ' . $missing->value . ' is not set.');
        $this->mint($config, $missing);
    }
}
