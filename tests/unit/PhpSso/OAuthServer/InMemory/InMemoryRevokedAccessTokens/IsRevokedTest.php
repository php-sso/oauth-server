<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRevokedAccessTokens;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemoryRevokedAccessTokens;

#[CoversMethod(InMemoryRevokedAccessTokens::class, 'isRevoked')]
final class IsRevokedTest extends TestCase
{
    public function testItIsFalseForATokenNobodyRevoked(): void
    {
        // Arrange
        $store = new InMemoryRevokedAccessTokens();
        $store->revoke('jti-1', 2_000_000_000);

        // Act
        $other = $store->isRevoked('jti-2');

        // Assert
        self::assertFalse($other);
    }
}
