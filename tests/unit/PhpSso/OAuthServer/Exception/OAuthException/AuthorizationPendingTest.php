<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'authorizationPending')]
final class AuthorizationPendingTest extends TestCase
{
    public function testItCarriesTheDeviceFlowErrorCode(): void
    {
        // Act
        $exception = OAuthException::authorizationPending();

        // Assert
        self::assertSame('authorization_pending', $exception->error);
        self::assertSame(400, $exception->httpStatus);
    }
}
