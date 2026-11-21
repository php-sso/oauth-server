<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'invalidToken')]
final class InvalidTokenTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Arrange
        $description = 'Something specific';

        // Act
        $exception = OAuthException::invalidToken($description);

        // Assert
        self::assertSame('invalid_token', $exception->error);
        self::assertSame($description, $exception->errorDescription);
        self::assertSame(401, $exception->httpStatus);
    }
}
