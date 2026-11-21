<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRefreshTokenStore;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;

#[CoversMethod(InMemoryRefreshTokenStore::class, 'revokeFamily')]
final class RevokeFamilyTest extends TestCase
{
    public function testItRevokesTheWholeFamilyAndNoOtherFamily(): void
    {
        // Arrange
        $store = new InMemoryRefreshTokenStore();

        // Act
        $store->revokeFamily('family-1', 1_700_000_200);

        // Assert
        self::assertTrue($store->isFamilyRevoked('family-1'));
        self::assertFalse($store->isFamilyRevoked('family-2'));
    }
}
