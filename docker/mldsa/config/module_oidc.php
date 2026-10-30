<?php

declare(strict_types=1);

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;

$default = getenv('MLDSA_DEFAULT_ALG') ?: 'ML-DSA-44';
$names = ['RS256', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
if (!in_array($default, $names, true)) {
    throw new RuntimeException('MLDSA_DEFAULT_ALG must be RS256 or one of the three ML-DSA variants.');
}
$ordered = array_values(array_unique([$default, ...$names]));
$keys = static function (string $profile, array $algorithms): array {
    return array_map(static function (string $name) use ($profile): array {
        $id = $profile . '-' . strtolower($name) . '-01';
        return [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::from($name),
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => $id . '.key',
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => $id . '.pub',
            ModuleConfig::KEY_KEY_ID => $id,
        ];
    }, $algorithms);
};
$config = [
    ModuleConfig::OPTION_ISSUER => 'https://localhost:8443',
    ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => $keys('protocol', $ordered),
    ModuleConfig::OPTION_FEDERATION_ENABLED => true,
    ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS => $keys(
        'federation',
        array_values(array_unique([$default === 'RS256' ? 'ML-DSA-44' : $default, ...$names])),
    ),
    ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS => [],
    ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER => null,
    ModuleConfig::OPTION_VCI_ENABLED => false,
    ModuleConfig::OPTION_AUTH_SOURCE => 'example-userpass',
    ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',
    ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
        'attribute' => 'eduPersonEntitlement',
        'client' => ['urn:example:oidc:manage:client'],
    ],
    ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
    ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',
    ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1D',
    ModuleConfig::OPTION_ENCRYPTION_KEY => trim(file_get_contents('/state/encryption-key')),
];
