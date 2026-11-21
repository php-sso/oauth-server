<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'accessDenied')]
final class AccessDeniedTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Arrange
        $description = 'Something specific';

        // Act
        $exception = OAuthException::accessDenied($description);

        // Assert
        self::assertSame('access_denied', $exception->error);
        self::assertSame($description, $exception->errorDescription);
        self::assertSame(403, $exception->httpStatus);
    }
}
