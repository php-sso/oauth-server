<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryRevokedAccessTokens;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemoryRevokedAccessTokens;

#[CoversMethod(InMemoryRevokedAccessTokens::class, 'revoke')]
final class RevokeTest extends TestCase
{
    public function testItRemembersARevokedToken(): void
    {
        // Arrange
        $store = new InMemoryRevokedAccessTokens();

        // Act
        $store->revoke('jti-1', 2_000_000_000);

        // Assert
        self::assertTrue($store->isRevoked('jti-1'));
    }
}
