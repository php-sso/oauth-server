<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'slowDown')]
final class SlowDownTest extends TestCase
{
    public function testItCarriesTheDeviceFlowErrorCode(): void
    {
        // Act
        $exception = OAuthException::slowDown();

        // Assert
        self::assertSame('slow_down', $exception->error);
        self::assertSame(400, $exception->httpStatus);
    }
}
