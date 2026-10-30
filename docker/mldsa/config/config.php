<?php

declare(strict_types=1);

$config = [
    'baseurlpath' => 'https://localhost:8443/simplesaml/',
    'certdir' => '/state/keys/',
    'cachedir' => '/state/cache/',
    'datadir' => '/state/data/',
    'tempdir' => '/state/tmp/',
    'secretsalt' => file_get_contents('/state/secretsalt'),
    'auth.adminpassword' => 'mldsa-admin',
    'database.dsn' => 'sqlite:/state/data/oidc.sqlite',
    'database.username' => null,
    'database.password' => null,
    'database.prefix' => 'oidc_',
    'logging.handler' => 'errorlog',
    'logging.level' => 7,
    'timezone' => 'Europe/Amsterdam',
    'module.enable' => ['core' => true, 'admin' => true, 'exampleauth' => true, 'oidc' => true],
    'session.cookie.secure' => true,
    'session.cookie.samesite' => 'Lax',
    'session.cookie.name' => 'MLDSALabSession',
    'session.phpsession.cookiename' => 'MLDSALabPHP',
    'store.type' => 'phpsession',
];
