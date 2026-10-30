<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Federation;

use Jose\Component\Core\Util\AKPKey;
use Jose\Component\KeyManagement\JWKFactory;
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
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;

#[CoversClass(EntityStatementController::class)]
#[CoversClass(FederationFactory::class)]
#[CoversClass(JwksFactory::class)]
#[CoversClass(JwksController::class)]
#[CoversClass(OpMetadataService::class)]
#[CoversClass(ModuleConfig::class)]
class MlDsaEntityStatementTest extends TestCase
{
    /** @var list<string> */
    private array $paths = [];


    protected function tearDown(): void
    {
        foreach ($this->paths as $path) {
            unlink($path);
        }
    }


    public static function algorithmProvider(): array
    {
        return [
            'ML-DSA-44' => [SignatureAlgorithmEnum::MLDSA44],
            'ML-DSA-65' => [SignatureAlgorithmEnum::MLDSA65],
            'ML-DSA-87' => [SignatureAlgorithmEnum::MLDSA87],
        ];
    }


    private function keyEntry(SignatureAlgorithmEnum $algorithm, string $kid): array
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped($algorithm->value . ' is not supported by this PHP/OpenSSL runtime.');
        }

        if ($algorithm === SignatureAlgorithmEnum::RS256) {
            $private = file_get_contents(dirname(__DIR__, 4) . '/cert/oidc_module.key');
            $this->assertNotFalse($private);
            $native = openssl_pkey_get_private($private);
        } elseif ($algorithm === SignatureAlgorithmEnum::ES256) {
            $native = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            $this->assertNotFalse($native);
            $this->assertTrue(openssl_pkey_export($native, $private));
        } else {
            $jwk = (new JWKFactory())->mldsa($algorithm->value);
            $private = AKPKey::convertPrivateKeyToPKCS8PEM($jwk);
            $public = AKPKey::convertPublicKeyToPEM($jwk);
        }
        if (isset($native)) {
            $this->assertNotFalse($native);
            $details = openssl_pkey_get_details($native);
            $this->assertNotFalse($details);
            $public = $details['key'];
        }

        $files = [];
        foreach ([$private, $public] as $pem) {
            $path = tempnam(sys_get_temp_dir(), 'oidc-key-selection-');
            $this->assertNotFalse($path);
            $this->paths[] = $path;
            $this->assertNotFalse(file_put_contents($path, $pem));
            $files[] = $path;
        }

        return [
            ModuleConfig::KEY_ALGORITHM => $algorithm,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => $files[0],
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => $files[1],
            ModuleConfig::KEY_KEY_ID => $kid,
        ];
    }


    private function config(array $entries, string $issuer = 'https://op.example.org'): ModuleConfig
    {
        return new ModuleConfig(overrides: [
            ModuleConfig::OPTION_ISSUER => $issuer,
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
        $this->assertNotContains($algorithm->value, $metadata['dpop_signing_alg_values_supported']);
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


    #[DataProvider('algorithmProvider')]
    public function testProcessesMixedAlgorithmTrustChains(SignatureAlgorithmEnum $algorithm): void
    {
        $ml = $this->keyEntry($algorithm, 'ml');
        $rsa = $this->keyEntry(SignatureAlgorithmEnum::RS256, 'rsa');
        // Exercise ML-DSA both as the leaf's algorithm and as the superior's signing algorithm.
        foreach ([[$ml, $rsa], [$rsa, $ml]] as [$leafEntry, $anchorEntry]) {
            $leafConfig = $this->config([$leafEntry]);
            $anchorConfig = $this->config([$anchorEntry], 'https://ta.example.org');
            [$leaf] = $this->publish($leafConfig);
            [$anchor] = $this->publish($anchorConfig);
            $federation = $this->federation($leafConfig);
            $pair = $anchorConfig->getFederationSignatureKeyPairBag()->getFirstOrFail();
            $subordinate = $federation->entityStatementFactory()->fromData(
                $pair->getKeyPair()->getPrivateKey(),
                $pair->getSignatureAlgorithm(),
                [
                    'iss' => $anchor->getIssuer(),
                    'sub' => $leaf->getIssuer(),
                    'iat' => time(),
                    'exp' => time() + 300,
                    'jwks' => $leaf->getJwks()->getValue(),
                    'metadata_policy' => [
                        'openid_provider' => ['organization_name' => ['value' => 'Federation policy']],
                    ],
                ],
                ['kid' => $pair->getKeyPair()->getKeyId()],
            );
            $subordinate = $federation->entityStatementFactory()->fromToken($subordinate->getToken());
            // The chain builder does not itself check the final subordinate-to-anchor signature.
            $subordinate->verifyWithKeySet($anchor->getJwks()->getValue());
            $this->assertSame($anchorEntry[ModuleConfig::KEY_ALGORITHM]->value, $subordinate->getHeaderClaim('alg'));
            $this->assertSame($anchorEntry[ModuleConfig::KEY_KEY_ID], $subordinate->getKeyId());
            $chain = $federation->trustChainFactory()->fromTokens(
                $leaf->getToken(),
                $subordinate->getToken(),
                $anchor->getToken(),
            );
            $this->assertSame(3, $chain->getResolvedLength());
            $this->assertSame($leaf->getIssuer(), $chain->getResolvedLeaf()->getIssuer());
            $this->assertSame($anchor->getIssuer(), $chain->getResolvedTrustAnchor()->getIssuer());
            $this->assertSame($subordinate->getExpirationTime(), $chain->getResolvedExpirationTime());
            $metadata = $chain->getResolvedMetadata(EntityTypesEnum::OpenIdProvider);
            $this->assertSame('Federation policy', $metadata['organization_name']);
            $this->assertSame(['RS256'], $metadata['id_token_signing_alg_values_supported']);

            $this->assertSignatureRejected(fn() => $federation->trustChainFactory()->fromTokens(
                $this->alterSignature($leaf),
                $subordinate->getToken(),
                $anchor->getToken(),
            ));
            $tampered = $federation->entityStatementFactory()->fromToken($this->alterSignature($subordinate));
            $this->assertSignatureRejected(fn() => $tampered->verifyWithKeySet($anchor->getJwks()->getValue()));
            // A valid superior signature must not endorse a different leaf key.
            $wrongEndorsement = $federation->entityStatementFactory()->fromData(
                $pair->getKeyPair()->getPrivateKey(),
                $pair->getSignatureAlgorithm(),
                array_replace($subordinate->getPayload(), ['jwks' => $anchor->getJwks()->getValue()]),
                ['kid' => $pair->getKeyPair()->getKeyId()],
            );
            $wrongEndorsement->verifyWithKeySet($anchor->getJwks()->getValue());
            $this->assertSignatureRejected(fn() => $federation->trustChainFactory()->fromTokens(
                $leaf->getToken(),
                $wrongEndorsement->getToken(),
                $anchor->getToken(),
            ));
        }
    }


    private function alterSignature(EntityStatement $statement): string
    {
        $parts = explode('.', $statement->getToken());
        $parts[2][0] = $parts[2][0] === 'A' ? 'B' : 'A';

        return implode('.', $parts);
    }


    private function assertSignatureRejected(callable $verify): void
    {
        try {
            $verify();
            $this->fail('An invalid Federation signature or unendorsed leaf key was accepted.');
        } catch (JwsException) {
            $this->addToAssertionCount(1);
        }
    }
}
