<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\VerificationKey;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\VerificationKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(VerificationKey::class, 'openSslKey')]
final class OpenSslKeyTest extends TestCase
{
    public function testItReturnsAKeyOpenSslCanVerifyWith(): void
    {
        // Arrange
        $key = TestKeys::signingKey()->verificationKey();

        // Act
        $openSslKey = $key->openSslKey();

        // Assert
        self::assertNotFalse(openssl_pkey_get_details($openSslKey));
    }
}
