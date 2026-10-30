<?php

declare(strict_types=1);

// Reuse the manual lab's storage and example users with a separate state volume.
require '/workspace/simplesamlphp-module-oidc/docker/mldsa/config/config.php';
$config['baseurlpath'] = 'https://op.127.0.0.1.nip.io:9443/simplesaml/';
$config['session.cookie.name'] = 'OIDFedLabSession';
$config['session.phpsession.cookiename'] = 'OIDFedLabPHP';
