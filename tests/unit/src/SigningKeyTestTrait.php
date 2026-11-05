<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use Jose\Component\Core\Util\AKPKey;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

/** Temporary PEM files for tests that load real configured signing keys. */
trait SigningKeyTestTrait
{
    /** @var list<string> */
    private array $keyPaths = [];


    protected function tearDown(): void
    {
        foreach ($this->keyPaths as $path) {
            unlink($path);
        }
        parent::tearDown();
    }


    private function keyFile(string $pem): string
    {
        $path = tempnam(sys_get_temp_dir(), 'oidc-signing-key-');
        $this->assertNotFalse($path);
        $this->keyPaths[] = $path;
        $this->assertNotFalse(file_put_contents($path, $pem));

        return $path;
    }


    private function keyEntry(SignatureAlgorithmEnum $algorithm, string $kid): array
    {
        if (!$algorithm->isSupported()) {
            $this->markTestSkipped($algorithm->value . ' is not supported by this PHP/OpenSSL runtime.');
        }

        if ($algorithm === SignatureAlgorithmEnum::RS256) {
            $private = file_get_contents(dirname(__DIR__, 2) . '/cert/oidc_module.key');
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

        return [
            ModuleConfig::KEY_ALGORITHM => $algorithm,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => $this->keyFile($private),
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => $this->keyFile($public),
            ModuleConfig::KEY_KEY_ID => $kid,
        ];
    }
}
