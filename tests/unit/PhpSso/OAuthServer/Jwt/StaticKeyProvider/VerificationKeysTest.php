<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\StaticKeyProvider;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(StaticKeyProvider::class, 'verificationKeys')]
final class VerificationKeysTest extends TestCase
{
    public function testItListsTheCurrentKeyFirstThenTheRetiredOnes(): void
    {
        // Arrange
        $retired = TestKeys::signingKey('old', 'b')->verificationKey();
        $provider = new StaticKeyProvider(TestKeys::signingKey('current'), [$retired]);

        // Act
        $kids = array_map(static fn ($key): string => $key->kid, $provider->verificationKeys());

        // Assert
        self::assertSame(['current', 'old'], $kids);
    }
}
