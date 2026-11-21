<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Exception\OAuthException;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;

#[CoversMethod(OAuthException::class, 'unsupportedTokenType')]
final class UnsupportedTokenTypeTest extends TestCase
{
    public function testItCarriesTheRfcErrorCodeAndStatus(): void
    {
        // Act
        $exception = OAuthException::unsupportedTokenType('Something specific');

        // Assert
        self::assertSame('unsupported_token_type', $exception->error);
        self::assertSame(400, $exception->httpStatus);
    }
}
