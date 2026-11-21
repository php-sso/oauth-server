<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'insufficientScope')]
final class InsufficientScopeTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Arrange
        $description = 'Something specific';

        // Act
        $exception = OAuthException::insufficientScope($description);

        // Assert
        self::assertSame('insufficient_scope', $exception->error);
        self::assertSame($description, $exception->errorDescription);
        self::assertSame(403, $exception->httpStatus);
    }
}
