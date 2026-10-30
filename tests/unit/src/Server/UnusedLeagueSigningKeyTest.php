<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server;

use LogicException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Server\UnusedLeagueSigningKey;

#[CoversClass(UnusedLeagueSigningKey::class)]
class UnusedLeagueSigningKeyTest extends TestCase
{
    #[DataProvider('getterProvider')]
    public function testRejectsKeyMaterialAccess(string $getter): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('protocol signing belongs to the OpenID library');

        (new UnusedLeagueSigningKey())->$getter();
    }


    public static function getterProvider(): array
    {
        return [
            ['getKeyPath'],
            ['getPassPhrase'],
            ['getKeyContents'],
        ];
    }
}
