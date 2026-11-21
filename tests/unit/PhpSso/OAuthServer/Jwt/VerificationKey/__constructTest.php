<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\VerificationKey;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\VerificationKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(VerificationKey::class, '__construct')]
final class __constructTest extends TestCase
{
    public function testItRejectsAnEmptyKid(): void
    {
        // Arrange
        $pem = TestKeys::signingKey()->verificationKey()->publicKeyPem;
        $this->expectException(InvalidArgumentException::class);

        // Act
        new VerificationKey('', $pem);
    }

    public function testItRejectsATextThatIsNotAPublicKey(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);

        // Act
        new VerificationKey('key-1', 'nope');
    }
}
