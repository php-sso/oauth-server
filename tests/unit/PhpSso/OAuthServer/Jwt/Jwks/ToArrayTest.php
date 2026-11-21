<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\Jwks;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\Jwks;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(Jwks::class, 'toArray')]
final class ToArrayTest extends TestCase
{
    public function testItPublishesEveryVerificationKey(): void
    {
        // Arrange
        $retired = TestKeys::signingKey('old', 'b')->verificationKey();
        $provider = new StaticKeyProvider(TestKeys::signingKey('current'), [$retired]);

        // Act
        $jwks = Jwks::toArray($provider);

        // Assert
        self::assertSame(['current', 'old'], array_column($jwks['keys'], 'kid'));
        self::assertArrayNotHasKey('d', $jwks['keys'][0]); // never the private part
    }
}
