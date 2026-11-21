<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'isFamilyRevoked')]
final class IsFamilyRevokedTest extends TestCase
{
    public function testItIsFalseUntilTheFamilyIsRevoked(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();

        // Act
        $before = $store->isFamilyRevoked('family-1');
        $store->revokeFamily('family-1', 1_700_000_200);
        $after = $store->isFamilyRevoked('family-1');

        // Assert
        self::assertFalse($before);
        self::assertTrue($after);
    }
}
