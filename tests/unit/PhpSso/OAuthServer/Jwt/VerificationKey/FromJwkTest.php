<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\VerificationKey;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\VerificationKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(VerificationKey::class, 'fromJwk')]
final class FromJwkTest extends TestCase
{
    public function testItBuildsTheSameKeyFromItsJwk(): void
    {
        // Arrange
        $original = TestKeys::signingKey('key-1')->verificationKey();

        // Act
        $rebuilt = VerificationKey::fromJwk($original->toJwk());

        // Assert
        self::assertSame($original->toJwk(), $rebuilt->toJwk());
    }

    public function testItVerifiesSignaturesMadeByTheMatchingPrivateKey(): void
    {
        // Arrange
        $signingKey = TestKeys::signingKey('key-1');
        $rebuilt = VerificationKey::fromJwk($signingKey->verificationKey()->toJwk());
        $privateKey = openssl_pkey_get_private($signingKey->privateKeyPem);
        self::assertNotFalse($privateKey);
        openssl_sign('message', $signature, $privateKey, OPENSSL_ALGO_SHA256);
        self::assertIsString($signature);

        // Act
        $result = openssl_verify('message', $signature, $rebuilt->openSslKey(), OPENSSL_ALGO_SHA256);

        // Assert
        self::assertSame(1, $result);
    }

    /** @param array<string, mixed> $jwk */
    #[DataProvider('unusableKeys')]
    public function testItRejectsAJwkItCannotUse(array $jwk): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);

        // Act
        VerificationKey::fromJwk($jwk);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function unusableKeys(): array
    {
        return [
            'not RSA' => [['kty' => 'EC', 'kid' => 'k', 'n' => 'AQAB', 'e' => 'AQAB']],
            'no kid' => [['kty' => 'RSA', 'n' => 'AQAB', 'e' => 'AQAB']],
            'no modulus' => [['kty' => 'RSA', 'kid' => 'k', 'e' => 'AQAB']],
            'bad base64url' => [['kty' => 'RSA', 'kid' => 'k', 'n' => 'a+b/', 'e' => 'AQAB']],
            'a modulus too small to be a real key' => [['kty' => 'RSA', 'kid' => 'k', 'n' => 'AQAB', 'e' => 'AQAB']],
        ];
    }
}
