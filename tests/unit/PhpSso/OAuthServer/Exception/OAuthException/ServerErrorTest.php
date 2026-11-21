<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'serverError')]
final class ServerErrorTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Arrange
        $description = 'Something specific';

        // Act
        $exception = OAuthException::serverError($description);

        // Assert
        self::assertSame('server_error', $exception->error);
        self::assertSame($description, $exception->errorDescription);
        self::assertSame(500, $exception->httpStatus);
    }
}
