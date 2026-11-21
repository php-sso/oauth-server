<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\VerificationKey;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\VerificationKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(VerificationKey::class, 'toJwk')]
final class ToJwkTest extends TestCase
{
    public function testItDescribesTheKeyAsAnRsaSigningJwk(): void
    {
        // Arrange
        $key = TestKeys::signingKey('key-1')->verificationKey();

        // Act
        $jwk = $key->toJwk();

        // Assert
        self::assertSame('RSA', $jwk['kty']);
        self::assertSame('sig', $jwk['use']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('key-1', $jwk['kid']);
        self::assertSame('AQAB', $jwk['e']); // 65537
        self::assertGreaterThan(300, strlen($jwk['n']));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $jwk['n']);
    }
}
