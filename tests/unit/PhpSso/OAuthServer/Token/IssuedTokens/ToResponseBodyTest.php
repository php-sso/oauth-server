<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\IssuedTokens;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\IssuedTokens;

#[CoversMethod(IssuedTokens::class, 'toResponseBody')]
final class ToResponseBodyTest extends TestCase
{
    public function testItProducesTheTokenResponseOfRfc6749(): void
    {
        // Arrange
        $tokens = new IssuedTokens('access', 3600, ['openid', 'profile'], 'refresh', 'id');

        // Act
        $body = $tokens->toResponseBody();

        // Assert
        self::assertSame([
            'access_token' => 'access',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'scope' => 'openid profile',
            'refresh_token' => 'refresh',
            'id_token' => 'id',
        ], $body);
    }

    public function testItLeavesOutTheTokensThatWereNotIssued(): void
    {
        // Arrange
        $tokens = new IssuedTokens('access', 60, ['api'], null, null);

        // Act
        $body = $tokens->toResponseBody();

        // Assert
        self::assertArrayNotHasKey('refresh_token', $body);
        self::assertArrayNotHasKey('id_token', $body);
    }
}
