<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Federation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Controllers\Federation\EntityStatementController;
use SimpleSAML\Module\oidc\Controllers\JwksController;
use SimpleSAML\Module\oidc\Factories\CacheFactory;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\Factories\JwksFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\CredentialIssuerMetadataService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Services\VcIssuerMetadataService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\ClassInstanceBuilder;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\Test\Module\oidc\unit\SigningKeyTestTrait;

#[CoversClass(EntityStatementController::class)]
#[CoversClass(FederationFactory::class)]
#[CoversClass(JwksFactory::class)]
#[CoversClass(JwksController::class)]
#[CoversClass(OpMetadataService::class)]
#[CoversClass(ModuleConfig::class)]
class MlDsaEntityStatementTest extends TestCase
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
            ModuleConfig::OPTION_FEDERATION_ENABLED => true,
            ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS => $entries,
            ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
                $this->keyEntry(SignatureAlgorithmEnum::RS256, 'protocol'),
            ],
            ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS => ['https://ta.example.org'],
            ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER => null,
            ModuleConfig::OPTION_FEDERATION_TRUST_MARK_TOKENS => [],
            ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS => [],
            ModuleConfig::OPTION_VCI_ENABLED => false,
        ]);
    }


    private function federation(ModuleConfig $config): Federation
    {
        $logger = new LoggerService();

        return (new FederationFactory(
            $config,
            $logger,
            new DestinationPolicyFactory($config, $logger),
            new CacheFactory($config, $logger, new ClassInstanceBuilder()),
        ))->build();
    }


    /** @return array{\SimpleSAML\OpenID\Federation\EntityStatement, array} */
    private function publish(ModuleConfig $config): array
    {
        $logger = new LoggerService();
        $jwks = (new JwksFactory($config, $logger, new DestinationPolicyFactory($config, $logger)))->build();
        // Only SSP's URL/locale boundaries and the unrelated credential services are doubles.
        $routes = $this->getMockBuilder(Routes::class)->disableOriginalConstructor()
            ->onlyMethods(['getModuleUrl'])->getMock();
        $routes->expects($this->atLeastOnce())->method('getModuleUrl')->willReturnCallback(
            fn(string $path = ''): string => $config->getIssuer() . '/' . $path,
        );
        $locales = $this->createStub(UiLocalesResolver::class);
        $locales->method('getSupportedUiLocales')->willReturn([]);
        $metadata = new OpMetadataService(
            $config,
            new ClaimTranslatorExtractor(['uid'], new ClaimSetEntityFactory()),
            $routes,
            $locales,
        );
        $vcMetadata = $this->createStub(VcIssuerMetadataService::class);
        $vcMetadata->method('getMetadata')->willThrowException(new RuntimeException('No credential keys configured.'));
        $controller = new EntityStatementController(
            $config,
            $jwks,
            $metadata,
            new Helpers(),
            $routes,
            $this->federation($config),
            $logger,
            null,
            $this->createStub(CredentialIssuerMetadataService::class),
            $vcMetadata,
        );
        $response = $controller->configuration();
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/entity-statement+jwt', $response->headers->get('Content-Type'));
        $statement = $this->federation($config)->entityStatementFactory()->fromToken($response->getContent());
        $keysResponse = (new JwksController($config, $jwks, $routes))();
        $this->assertSame(200, $keysResponse->getStatusCode());
        $keys = json_decode($keysResponse->getContent(), true, 512, JSON_THROW_ON_ERROR);

        return [$statement, $keys];
    }


    #[DataProvider('algorithmProvider')]
    public function testPublishesVerifiableFederationConfiguration(SignatureAlgorithmEnum $algorithm): void
    {
        $entry = $this->keyEntry($algorithm, 'federation');
        $config = $this->config([$entry]);
        $before = time();
        [$statement, $published] = $this->publish($config);
        $statement->verifyWithKeySet();
        $statement->verifyWithKeySet($published);
        $this->assertSame('entity-statement+jwt', $statement->getHeaderClaim('typ'));
        $this->assertSame($algorithm->value, $statement->getHeaderClaim('alg'));
        $this->assertSame('federation', $statement->getKeyId());
        $this->assertSame($config->getIssuer(), $statement->getIssuer());
        $this->assertSame($config->getIssuer(), $statement->getSubject());
        $this->assertGreaterThanOrEqual($before, $statement->getIssuedAt());
        $this->assertLessThanOrEqual(time(), $statement->getIssuedAt());
        $this->assertGreaterThan($statement->getIssuedAt(), $statement->getExpirationTime());
        $this->assertNotEmpty($statement->getPayloadClaim('jti'));
        $this->assertSame(['https://ta.example.org'], $statement->getAuthorityHints());
        $embedded = $statement->getJwks()->getValue();
        $this->assertSame(['federation'], array_column($embedded['keys'], 'kid'));
        $key = $embedded['keys'][0];
        $this->assertSame($algorithm->value, $key['alg']);
        $this->assertSame('AKP', $key['kty']);
        $this->assertNotEmpty($key['pub']);
        $this->assertEqualsCanonicalizing(['alg', 'kid', 'kty', 'pub', 'use'], array_keys($key));
        $this->assertContains($key, $published['keys']);
        $this->assertSame(['protocol', 'federation'], array_column($published['keys'], 'kid'));
        $metadata = $statement->getMetadata()['openid_provider'];
        $this->assertSame(['RS256'], $metadata['id_token_signing_alg_values_supported']);
        $this->assertSame(['automatic'], $metadata['client_registration_types_supported']);
        $this->assertSame($config->getIssuer(), $metadata['issuer']);
        $this->assertContains($algorithm->value, $metadata['dpop_signing_alg_values_supported']);
    }


    #[DataProvider('algorithmProvider')]
    public function testRotatesFederationKeysIndependentlyOfProtocolKeys(SignatureAlgorithmEnum $algorithm): void
    {
        $old = $this->keyEntry($algorithm, 'old');
        $new = $this->keyEntry($algorithm, 'new');
        $ec = $this->keyEntry(SignatureAlgorithmEnum::ES256, 'ec');
        [$previous] = $this->publish($this->config([$old, $ec]));
        [$current, $published] = $this->publish($this->config([$new, $ec, $old]));
        $retained = $current->getJwks()->getValue();
        $this->assertSame(['new', 'ec', 'old'], array_column($retained['keys'], 'kid'));
        $this->assertSame('old', $previous->getKeyId());
        $this->assertSame('new', $current->getKeyId());
        $this->assertSame($algorithm->value, $current->getHeaderClaim('alg'));
        foreach ([$previous, $current] as $statement) {
            $statement->verifyWithKeySet($retained);
            $statement->verifyWithKeySet($published);
        }
        [$ecDefault] = $this->publish($this->config([$ec, $new, $old]));
        $ecDefault->verifyWithKeySet();
        $this->assertSame('ES256', $ecDefault->getHeaderClaim('alg'));
        $this->assertSame('ec', $ecDefault->getKeyId());
        [$withdrawn, $published] = $this->publish($this->config([$new, $ec]));
        $current->verifyWithKeySet($withdrawn->getJwks()->getValue());
        $this->assertSame(['new', 'ec'], array_column($withdrawn->getJwks()->getValue()['keys'], 'kid'));
        $this->expectException(JwsException::class);
        $previous->verifyWithKeySet($published);
    }
}
