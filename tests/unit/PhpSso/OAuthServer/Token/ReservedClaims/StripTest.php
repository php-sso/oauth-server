<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\ReservedClaims;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\ReservedClaims;

#[CoversMethod(ReservedClaims::class, 'strip')]
final class StripTest extends TestCase
{
    public function testItDropsTheClaimsTheLibraryControls(): void
    {
        // Arrange
        $claims = ['iss' => 'x', 'sub' => 'x', 'aud' => 'x', 'exp' => 1, 'nonce' => 'x', 'sid' => 'x', 'scope' => 'x', 'gty' => 'x', 'name' => 'Alice'];

        // Act
        $kept = ReservedClaims::strip($claims);

        // Assert
        self::assertSame(['name' => 'Alice'], $kept);
    }

    public function testItKeepsEverythingElse(): void
    {
        // Arrange
        $claims = ['name' => 'Alice', 'email' => 'a@example.com', 'groups' => ['staff']];

        // Act
        $kept = ReservedClaims::strip($claims);

        // Assert
        self::assertSame($claims, $kept);
    }
}
