<?php

declare(strict_types=1);

require '/workspace/simplesamlphp-module-oidc/vendor/autoload.php';

use Defuse\Crypto\Key;
use Jose\Component\Core\Util\AKPKey;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

foreach (['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as $name) {
    if (!SignatureAlgorithmEnum::from($name)->isSupported()) {
        throw new RuntimeException($name . ' is unavailable in the container PHP/OpenSSL runtime.');
    }
    echo $name, ': available', PHP_EOL;
}
foreach (
    ['/state/secretsalt' => bin2hex(random_bytes(32)),
    '/state/encryption-key' => Key::createNewRandomKey()->saveToAsciiSafeString()] as $file => $value
) {
    if (!file_exists($file)) {
        file_put_contents($file, $value);
    }
}
foreach (['protocol', 'federation'] as $profile) {
    foreach (['RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as $algorithm) {
        $path = '/state/keys/' . $profile . '-' . strtolower($algorithm) . '-01';
        if (!file_exists($path . '.key')) {
            if ($algorithm === 'RS256') {
                $native = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 3072]);
                if ($native === false || !openssl_pkey_export($native, $private)) {
                    throw new RuntimeException('Could not generate RSA key.');
                }
                $public = openssl_pkey_get_details($native)['key'];
            } else {
                $jwk = (new JWKFactory())->mldsa($algorithm);
                $private = AKPKey::convertPrivateKeyToPKCS8PEM($jwk);
                $public = AKPKey::convertPublicKeyToPEM($jwk);
            }
            file_put_contents($path . '.key', $private);
            file_put_contents($path . '.pub', $public);
        }
    }
}
(new DatabaseMigration())->migrate();
$config = new ModuleConfig();
$factory = new ClientEntityFactory(new SspBridge(), new Helpers(), $config);
$repository = new ClientRepository(
    $config,
    Database::getInstance(),
    null,
    $factory,
    new AllowedOriginRepository($config, Database::getInstance(), null),
);
foreach (
    [
    'default' => null,
    'rsa' => 'RS256',
    '44' => 'ML-DSA-44',
    '65' => 'ML-DSA-65',
    '87' => 'ML-DSA-87',
    ] as $id => $algorithm
) {
    $client = $factory->fromData(
        id: 'burp-' . $id,
        secret: '',
        name: 'Burp lab ' . $id,
        description: 'Local public client using authorization code and S256 PKCE.',
        redirectUri: ['https://localhost:8443/callback.html'],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        isEnabled: true,
        isConfidential: false,
        extraMetadata: $algorithm === null ? null : ['id_token_signed_response_alg' => $algorithm],
    );
    $repository->findById($client->getIdentifier()) === null ? $repository->add($client) : $repository->update($client);
    echo 'Ready: ', $client->getIdentifier(), PHP_EOL;
}
