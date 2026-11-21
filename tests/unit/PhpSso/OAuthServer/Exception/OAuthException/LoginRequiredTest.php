<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'loginRequired')]
final class LoginRequiredTest extends TestCase
{
    public function testItCarriesTheOpenIdConnectErrorCode(): void
    {
        // Act
        $exception = OAuthException::loginRequired('Nobody is signed in.');

        // Assert
        self::assertSame('login_required', $exception->error);
        self::assertSame(400, $exception->httpStatus);
    }
}
