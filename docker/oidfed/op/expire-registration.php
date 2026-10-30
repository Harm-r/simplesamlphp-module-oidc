<?php

declare(strict_types=1);

require '/workspace/simplesamlphp-module-oidc/vendor/autoload.php';

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

// Force this lab's RP through automatic registration on the next login, so
// an algorithm change does not wait for the previous metadata to expire.
$database = Database::getInstance();
$database->write(
    'UPDATE ' . $database->applyPrefix(ClientRepository::TABLE_NAME) .
    ' SET expires_at = :expires WHERE id = :id AND registration_type = :type',
    [
        'expires' => '2000-01-01 00:00:00',
        'id' => 'https://rp.127.0.0.1.nip.io:9443',
        'type' => RegistrationTypeEnum::FederatedAutomatic->value,
    ],
);
