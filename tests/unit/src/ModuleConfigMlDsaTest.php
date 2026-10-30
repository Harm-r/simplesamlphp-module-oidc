<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use Jose\Component\Core\Exception\InvalidKeyException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\Utils\Config;

#[CoversClass(ModuleConfig::class)]
#[AllowMockObjectsWithoutExpectations]
class ModuleConfigMlDsaTest extends TestCase
{
    /** @var list<string> */
    private array $paths = [];


    protected function tearDown(): void
    {
        foreach ($this->paths as $path) {
            unlink($path);
        }
    }


    private function keyFile(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'oidc-mldsa-config-');
        $this->assertNotFalse($path);
        $this->paths[] = $path;
        $this->assertNotFalse(file_put_contents($path, $contents));

        return $path;
    }


    private function key(SignatureAlgorithmEnum $algorithm): JWK
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped($algorithm->value . ' is not supported by this PHP/OpenSSL runtime.');
        }

        return (new JWKFactory())->mldsa($algorithm->value);
    }


    private function config(
        string $option,
        SignatureAlgorithmEnum $algorithm,
        string $privatePem,
        string $publicPem,
        ?string $keyId = 'configured-mldsa-key',
    ): ModuleConfig {
        $utilsConfig = $this->createStub(Config::class);
        $utilsConfig->method('getCertPath')->willReturnArgument(0);
        $utils = $this->createStub(Utils::class);
        $utils->method('config')->willReturn($utilsConfig);
        $bridge = $this->createStub(SspBridge::class);
        $bridge->method('utils')->willReturn($utils);

        return new ModuleConfig(
            overrides: [$option => [[
                ModuleConfig::KEY_ALGORITHM => $algorithm,
                ModuleConfig::KEY_PRIVATE_KEY_FILENAME => $this->keyFile($privatePem),
                ModuleConfig::KEY_PUBLIC_KEY_FILENAME => $this->keyFile($publicPem),
                ModuleConfig::KEY_KEY_ID => $keyId,
            ]]],
            sspConfig: $this->createStub(Configuration::class),
            sspBridge: $bridge,
        );
    }


    private function load(ModuleConfig $config, string $option): SignatureKeyPairBag
    {
        return $option === ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS
        ? $config->getProtocolSignatureKeyPairBag()
        : $config->getFederationSignatureKeyPairBag();
    }


    public static function configurationProvider(): iterable
    {
        $options = [
            'protocol' => ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS,
            'federation' => ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS,
        ];
        $algorithms = [
            SignatureAlgorithmEnum::MLDSA44,
            SignatureAlgorithmEnum::MLDSA65,
            SignatureAlgorithmEnum::MLDSA87,
        ];

        foreach ($options as $name => $option) {
            foreach ($algorithms as $algorithm) {
                yield $name . ' ' . $algorithm->value => [$option, $algorithm];
            }
        }
    }


    public function testMlDsaIsOptInAndDependsOnRuntimeSupport(): void
    {
        $config = new ModuleConfig(sspConfig: $this->createStub(Configuration::class));
        $legacy = $config->getSupportedAlgorithms()->getSignatureAlgorithmBag()->getAllNamesUnique();
        $openId = $config->getSupportedAlgorithms(includeMlDsa: true)->getSignatureAlgorithmBag()->getAllNamesUnique();

        $this->assertSame($legacy, $config->getDpopSigningAlgorithms());
        $this->assertSame(array_values(array_intersect($openId, $legacy)), $legacy);
        $algorithms = [
            SignatureAlgorithmEnum::MLDSA44,
            SignatureAlgorithmEnum::MLDSA65,
            SignatureAlgorithmEnum::MLDSA87,
        ];
        foreach ($algorithms as $algorithm) {
            $this->assertNotContains($algorithm->value, $legacy);
            $this->assertSame($algorithm->isSupported(), in_array($algorithm->value, $openId, true));
        }
    }


    #[DataProvider('configurationProvider')]
    public function testLoadsAndUsesConfiguredKeyPair(string $option, SignatureAlgorithmEnum $algorithm): void
    {
        $key = $this->key($algorithm);
        $config = $this->config(
            $option,
            $algorithm,
            AKPKey::convertPrivateKeyToPKCS8PEM($key),
            AKPKey::convertPublicKeyToPEM($key),
        );
        $bag = $this->load($config, $option);
        $pair = $bag->getFirstOrFail();
        $this->assertSame($bag, $this->load($config, $option));
        $this->assertSame($algorithm, $pair->getSignatureAlgorithm());
        $this->assertSame('configured-mldsa-key', $pair->getKeyPair()->getKeyId());
        $this->assertSame($key->get('priv'), $pair->getKeyPair()->getPrivateKey()->jwk()->get('priv'));
        $publicKey = $pair->getKeyPair()->getPublicKey()->jsonSerialize();
        $this->assertSame('AKP', $publicKey['kty']);
        $this->assertSame($algorithm->value, $publicKey['alg']);
        $this->assertSame('configured-mldsa-key', $publicKey['kid']);
        $this->assertSame('sig', $publicKey['use']);
        $this->assertSame($key->get('pub'), $publicKey['pub']);
        $this->assertArrayNotHasKey('priv', $publicKey);

        $jws = new Jws($config->getSupportedAlgorithms(includeMlDsa: true));
        $signed = $jws->jwsDecoratorBuilder()->fromData(
            $pair->getKeyPair()->getPrivateKey(),
            $pair->getSignatureAlgorithm(),
            ['sub' => 'configuration-test'],
            ['kid' => $pair->getKeyPair()->getKeyId()],
        );
        $signatureLengths = ['ML-DSA-44' => 2420, 'ML-DSA-65' => 3309, 'ML-DSA-87' => 4627];
        $this->assertSame(
            $signatureLengths[$algorithm->value],
            strlen($signed->jws()->getSignature(0)->getSignature()),
        );
        $publicKeys = $jws->jwksDecoratorFactory()->fromKeySetData(['keys' => [$publicKey]]);
        $this->assertTrue($jws->jwsVerifierDecorator()->verifyWithKeySet($signed, $publicKeys, 0));
        $wrongKey = $this->key($algorithm)->toPublic()->all();
        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet(
            $signed,
            $jws->jwksDecoratorFactory()->fromKeySetData(['keys' => [$wrongKey]]),
            0,
        ));

        $serialized = $jws->jwsSerializerManagerDecorator()->serialize('jws_compact', $signed);
        $segments = explode('.', $serialized);
        $segments[1] = rtrim(strtr(base64_encode('{"sub":"tampered"}'), '+/', '-_'), '=');
        $tampered = $jws->jwsDecoratorBuilder()->fromToken(implode('.', $segments));
        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet($tampered, $publicKeys, 0));

        $segments = explode('.', $serialized);
        $segments[2] = rtrim(strtr(base64_encode(substr(
            $signed->jws()->getSignature(0)->getSignature(),
            0,
            -1,
        )), '+/', '-_'), '=');
        $truncated = $jws->jwsDecoratorBuilder()->fromToken(implode('.', $segments));
        $this->assertFalse($jws->jwsVerifierDecorator()->verifyWithKeySet($truncated, $publicKeys, 0));
    }


    #[DataProvider('configurationProvider')]
    public function testDerivesKeyIdFromPublicKey(string $option, SignatureAlgorithmEnum $algorithm): void
    {
        $key = $this->key($algorithm);
        $config = $this->config(
            $option,
            $algorithm,
            AKPKey::convertPrivateKeyToPKCS8PEM($key),
            AKPKey::convertPublicKeyToPEM($key),
            keyId: null,
        );

        $pair = $this->load($config, $option)->getFirstOrFail();
        // Compute RFC 7638/9964's canonical input independently of the library thumbprint helper.
        $canonical = json_encode([
            'alg' => $algorithm->value,
            'kty' => 'AKP',
            'pub' => $key->get('pub'),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $expected = rtrim(strtr(base64_encode(hash('sha256', $canonical, true)), '+/', '-_'), '=');
        $this->assertSame($expected, $pair->getKeyPair()->getKeyId());
    }


    #[DataProvider('configurationProvider')]
    public function testRejectsKeyForAnotherAlgorithmWhenSigning(
        string $option,
        SignatureAlgorithmEnum $algorithm,
    ): void {
        $otherAlgorithm = $algorithm === SignatureAlgorithmEnum::MLDSA44
        ? SignatureAlgorithmEnum::MLDSA65
        : SignatureAlgorithmEnum::MLDSA44;
        $key = $this->key($otherAlgorithm);
        $config = $this->config(
            $option,
            $algorithm,
            AKPKey::convertPrivateKeyToPKCS8PEM($key),
            AKPKey::convertPublicKeyToPEM($key),
        );
        $pair = $this->load($config, $option)->getFirstOrFail();

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('cannot be used with');
        $pair->getSignatureAlgorithm()->instance()->sign($pair->getKeyPair()->getPrivateKey()->jwk(), 'test');
    }


    public static function invalidMlDsaKeyProvider(): iterable
    {
        $algorithms = [
            SignatureAlgorithmEnum::MLDSA44,
            SignatureAlgorithmEnum::MLDSA65,
            SignatureAlgorithmEnum::MLDSA87,
        ];
        foreach ($algorithms as $algorithm) {
            yield $algorithm->value . ' short seed' => [$algorithm, 'short'];
            yield $algorithm->value . ' long seed' => [$algorithm, 'long'];
            yield $algorithm->value . ' inconsistent public key' => [$algorithm, 'public'];
        }
    }


    #[DataProvider('invalidMlDsaKeyProvider')]
    public function testSigningRejectsInvalidMlDsaKeyMaterial(SignatureAlgorithmEnum $algorithm, string $fault): void
    {
        $key = $this->key($algorithm)->all();
        if ($fault === 'public') {
            $key['pub'] = $this->key($algorithm)->get('pub');
        } else {
            $key['priv'] = rtrim(strtr(base64_encode(str_repeat('a', $fault === 'short' ? 31 : 33)), '+/', '-_'), '=');
        }

        $this->expectException(InvalidKeyException::class);
        $algorithm->instance()->sign(new JWK($key), 'invalid-key-test');
    }


    #[DataProvider('configurationProvider')]
    public function testRejectsInvalidPrivatePem(string $option, SignatureAlgorithmEnum $algorithm): void
    {
        $key = $this->key($algorithm);
        $config = $this->config($option, $algorithm, 'invalid PEM', AKPKey::convertPublicKeyToPEM($key));

        $this->expectException(InvalidKeyException::class);
        $this->load($config, $option);
    }


    #[DataProvider('configurationProvider')]
    public function testRejectsInvalidPublicPem(string $option, SignatureAlgorithmEnum $algorithm): void
    {
        $key = $this->key($algorithm);
        $config = $this->config($option, $algorithm, AKPKey::convertPrivateKeyToPKCS8PEM($key), 'invalid PEM');

        $this->expectException(InvalidKeyException::class);
        $this->load($config, $option);
    }
}
