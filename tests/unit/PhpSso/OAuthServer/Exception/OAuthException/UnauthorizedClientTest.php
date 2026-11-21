<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'unauthorizedClient')]
final class UnauthorizedClientTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Arrange
        $description = 'Something specific';

        // Act
        $exception = OAuthException::unauthorizedClient($description);

        // Assert
        self::assertSame('unauthorized_client', $exception->error);
        self::assertSame($description, $exception->errorDescription);
        self::assertSame(400, $exception->httpStatus);
    }
}
