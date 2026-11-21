<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'save')]
final class SaveTest extends TestCase
{
    public function testItStoresTheTokenUnderItsHash(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();
        $token = $this->token('hash-9');

        // Act
        $store->save($token);

        // Assert
        self::assertSame($token, $store->find('hash-9'));
    }

    private function token(string $hash = 'hash-1', string $family = 'family-1', ?string $session = 'session-1'): RefreshTokenRecord
    {
        return new RefreshTokenRecord($hash, $family, 'client-1', 'user-1', ['openid'], $session, 1_700_000_600, null, null);
    }
}
