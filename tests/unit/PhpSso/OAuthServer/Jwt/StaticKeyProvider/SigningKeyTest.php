<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\StaticKeyProvider;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(StaticKeyProvider::class, 'signingKey')]
final class SigningKeyTest extends TestCase
{
    public function testItReturnsTheKeyItWasBuiltWith(): void
    {
        // Arrange
        $signingKey = TestKeys::signingKey('current');
        $provider = new StaticKeyProvider($signingKey);

        // Act
        $result = $provider->signingKey();

        // Assert
        self::assertSame($signingKey, $result);
    }
}
