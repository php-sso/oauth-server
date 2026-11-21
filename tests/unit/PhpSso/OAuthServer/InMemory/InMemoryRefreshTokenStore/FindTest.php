<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'find')]
final class FindTest extends TestCase
{
    public function testItFindsASavedTokenByItsHash(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();
        $token = $this->token();
        $store->save($token);

        // Act
        $found = $store->find('hash-1');

        // Assert
        self::assertSame($token, $found);
    }

    public function testItReturnsNullForAnUnknownToken(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();

        // Act
        $found = $store->find('nope');

        // Assert
        self::assertNull($found);
    }

    private function token(string $hash = 'hash-1', string $family = 'family-1', ?string $session = 'session-1'): RefreshTokenRecord
    {
        return new RefreshTokenRecord($hash, $family, 'client-1', 'user-1', ['openid'], $session, 1_700_000_600, null, null);
    }
}
