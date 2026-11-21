<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\SigningKey;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\SigningKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(SigningKey::class, 'verificationKey')]
final class VerificationKeyTest extends TestCase
{
    public function testItDerivesThePublicKeyWithTheSameKid(): void
    {
        // Arrange
        $signingKey = TestKeys::signingKey('key-1');

        // Act
        $verificationKey = $signingKey->verificationKey();

        // Assert
        self::assertSame('key-1', $verificationKey->kid);
        self::assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $verificationKey->publicKeyPem);
    }
}
