<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server;

use League\OAuth2\Server\CryptKeyInterface;
use LogicException;

/**
 * Satisfies League's required key argument. The OpenID library handles protocol signing and verification.
 */
final class UnusedLeagueSigningKey implements CryptKeyInterface
{
    public function getKeyPath(): string
    {
        throw new LogicException('League signing keys are unused; protocol signing belongs to the OpenID library.');
    }


    public function getPassPhrase(): ?string
    {
        throw new LogicException('League signing keys are unused; protocol signing belongs to the OpenID library.');
    }


    public function getKeyContents(): string
    {
        throw new LogicException('League signing keys are unused; protocol signing belongs to the OpenID library.');
    }
}
