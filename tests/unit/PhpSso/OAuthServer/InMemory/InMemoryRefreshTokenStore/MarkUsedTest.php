<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'markUsed')]
final class MarkUsedTest extends TestCase
{
    public function testItMarksATokenAsExchangedOnlyOnce(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();
        $store->save($this->token());

        // Act
        $first = $store->markUsed('hash-1', 1_700_000_100);
        $second = $store->markUsed('hash-1', 1_700_000_101);

        // Assert
        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame(1_700_000_100, $store->find('hash-1')?->usedAt);
    }

    public function testItRefusesAnUnknownToken(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();

        // Act
        $result = $store->markUsed('nope', 1_700_000_100);

        // Assert
        self::assertFalse($result);
    }

    private function token(string $hash = 'hash-1', string $family = 'family-1', ?string $session = 'session-1'): RefreshTokenRecord
    {
        return new RefreshTokenRecord($hash, $family, 'client-1', 'user-1', ['openid'], $session, 1_700_000_600, null, null);
    }
}
