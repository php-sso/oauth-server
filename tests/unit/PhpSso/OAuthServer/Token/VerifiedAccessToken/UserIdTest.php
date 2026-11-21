<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\VerifiedAccessToken;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Token\VerifiedAccessToken;

#[CoversMethod(VerifiedAccessToken::class, 'userId')]
final class UserIdTest extends TestCase
{
    public function testItIsTheSubjectForATokenIssuedToAPerson(): void
    {
        // Arrange
        $token = new VerifiedAccessToken('iss', 'user-1', 'aud', 'web', ['openid'], GrantType::AuthorizationCode, 'jti', 100, 50, 'fid', 'sid');

        // Act
        $userId = $token->userId();

        // Assert
        self::assertSame('user-1', $userId);
    }

    public function testItIsNullForAClientCredentialsToken(): void
    {
        // Arrange
        $token = new VerifiedAccessToken('iss', 'service', 'aud', 'service', ['api'], GrantType::ClientCredentials, 'jti', 100, 50, null, null);

        // Act
        $userId = $token->userId();

        // Assert
        self::assertNull($userId);
    }
}
