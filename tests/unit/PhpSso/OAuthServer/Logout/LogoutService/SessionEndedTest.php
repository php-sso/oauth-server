<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Logout\LogoutService;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Logout\LogoutService;
use PhpSso\OAuthServer\Tests\Support\CapturingHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(LogoutService::class, 'sessionEnded')]
final class SessionEndedTest extends TestCase
{
    public function testItRevokesTheTokensOfTheSessionAndTellsTheClients(): void
    {
        // Arrange
        $t = new TestServer();
        $tokens = $t->signIn();
        $family = $t->str((new JwtDecoder($t->keys))->decode($t->str($tokens, 'access_token'))['claims'], 'fid');

        // Act
        $deliveries = $t->server->logoutService()->sessionEnded('session-1', 'user-1');

        // Assert
        self::assertTrue($t->refreshTokens->isFamilyRevoked($family));
        self::assertCount(1, $deliveries);
        self::assertTrue($deliveries[0]->delivered);
    }

    public function testTheAccessTokenStopsWorkingRightAway(): void
    {
        // Arrange
        $t = new TestServer();
        $access = $t->str($t->signIn(), 'access_token');
        $t->server->logoutService()->sessionEnded('session-1', 'user-1');
        $request = (new ServerRequest([], [], '/api', 'GET'))->withHeader('Authorization', 'Bearer ' . $access);

        // Act
        $response = $t->server->bearerTokenMiddleware()->process($request, new CapturingHandler());

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testTheRefreshTokenStopsWorkingToo(): void
    {
        // Arrange
        $t = new TestServer();
        $refresh = $t->str($t->signIn(), 'refresh_token');
        $t->server->logoutService()->sessionEnded('session-1', 'user-1');

        // Act
        $response = $t->token(['grant_type' => 'refresh_token', 'refresh_token' => $refresh], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_grant', $t->json($response)['error']);
    }
}
