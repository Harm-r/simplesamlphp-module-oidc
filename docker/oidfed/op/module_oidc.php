<?php

declare(strict_types=1);

use SimpleSAML\Module\oidc\ModuleConfig;

require '/workspace/simplesamlphp-module-oidc/docker/mldsa/config/module_oidc.php';
$anchor = 'https://ta.127.0.0.1.nip.io:9443';
$config[ModuleConfig::OPTION_ISSUER] = 'https://op.127.0.0.1.nip.io:9443';
$config[ModuleConfig::OPTION_DISPLAY_NAME] = 'SSP ML-DSA lab OP';
$config[ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS] = [$anchor];
$config[ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS] = [
    $anchor => is_file('/shared/ta-jwks.json') ? file_get_contents('/shared/ta-jwks.json') : null,
];
$config[ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS] = [
    'ta.127.0.0.1.nip.io', 'rp.127.0.0.1.nip.io', 'op.127.0.0.1.nip.io',
];
$config[ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS] = ['verify' => '/pki/ca.crt'];
$config[ModuleConfig::OPTION_PROTOCOL_HTTP_CLIENT_OPTIONS] = ['verify' => '/pki/ca.crt'];

$config[ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER] = \Symfony\Component\Cache\Adapter\FilesystemAdapter::class;
$config[ModuleConfig::OPTION_FEDERATION_CACHE_ADAPTER_ARGUMENTS] = ['oidfed-lab', 0, '/state/cache/federation'];
