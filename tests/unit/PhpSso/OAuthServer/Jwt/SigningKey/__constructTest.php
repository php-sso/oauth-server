<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\SigningKey;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\SigningKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(SigningKey::class, '__construct')]
final class __constructTest extends TestCase
{
    public function testItAcceptsAnRsaKeyOfAtLeast2048Bits(): void
    {
        // Act
        $key = new SigningKey('key-1', TestKeys::privatePem());

        // Assert
        self::assertSame('key-1', $key->kid);
    }

    public function testItRejectsAKeyThatIsNotPem(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);

        // Act
        new SigningKey('key-1', 'not a key');
    }

    public function testTheKeyDoesNotShowUpInTheTraceOfAnExceptionItCaused(): void
    {
        // Arrange
        $secret = 'MARKER-that-must-not-leak-into-traces';

        // Act
        try {
            new SigningKey('key-1', $secret);
            self::fail('A key that is not PEM must be rejected.');
        } catch (InvalidArgumentException $e) {
            $trace = print_r($e->getTrace(), true); // the whole arguments, not the shortened ones of getTraceAsString()
        }

        // Assert
        self::assertStringContainsString('SigningKey', $trace);
        self::assertStringNotContainsString($secret, $trace);
    }

    public function testItRejectsAnEmptyKid(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);

        // Act
        new SigningKey('', TestKeys::privatePem());
    }

    public function testItRejectsAnRsaKeyThatIsTooShort(): void
    {
        // Arrange
        $short = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($short);
        openssl_pkey_export($short, $pem);
        self::assertIsString($pem);
        $this->expectException(InvalidArgumentException::class);

        // Act
        new SigningKey('key-1', $pem);
    }

    public function testItRejectsAnEllipticCurveKey(): void
    {
        // Arrange
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($ec);
        openssl_pkey_export($ec, $pem);
        self::assertIsString($pem);
        $this->expectException(InvalidArgumentException::class);

        // Act
        new SigningKey('key-1', $pem);
    }
}
