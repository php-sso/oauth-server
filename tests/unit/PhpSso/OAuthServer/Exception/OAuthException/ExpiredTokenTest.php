<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'expiredToken')]
final class ExpiredTokenTest extends TestCase
{
    public function testItCarriesTheDeviceFlowErrorCode(): void
    {
        // Act
        $exception = OAuthException::expiredToken();

        // Assert
        self::assertSame('expired_token', $exception->error);
        self::assertSame(400, $exception->httpStatus);
    }
}
