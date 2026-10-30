<?php

declare(strict_types=1);

// Lab-only observation of response headers. Return the response byte-for-byte;
// do not log bearer tokens, authorization codes or private key material.
ob_start(static function (string $output): string {
    try {
        $data = json_decode($output, true);
        $tokens = [];
        if (is_array($data)) {
            foreach (['id_token', 'access_token'] as $name) {
                if (isset($data[$name]) && is_string($data[$name])) {
                    $tokens[$name] = $data[$name];
                }
            }
        } elseif (substr_count(trim($output), '.') === 2) {
            $tokens['statement'] = trim($output);
        }
        foreach ($tokens as $name => $token) {
            $parts = explode('.', $token);
            $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
            if (is_array($header)) {
                error_log('OIDFED_LAB_SIGNING ' . json_encode([
                    'artifact' => $name,
                    'alg' => $header['alg'] ?? null,
                    'kid' => $header['kid'] ?? null,
                    'typ' => $header['typ'] ?? null,
                ], JSON_THROW_ON_ERROR));
            }
        }
    } catch (Throwable) {
        // Observation must not change the endpoint's response or success/failure.
    }
    return $output;
});
