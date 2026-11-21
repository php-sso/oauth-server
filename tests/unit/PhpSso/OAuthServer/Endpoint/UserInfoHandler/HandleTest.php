<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\UserInfoHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\UserInfoHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(UserInfoHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testItReturnsTheClaimsForTheGrantedScopes(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn('openid profile email'), 'access_token');

        // Act
        $response = $this->call($token);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['sub' => 'user-1', 'name' => 'Alice Example', 'email' => 'alice@example.com'], $this->t->json($response));
    }

    public function testItReturnsTheClaimsThatDependOnTheClientTheTokenWasIssuedTo(): void
    {
        // Arrange
        $this->t->claims->clientClaims['web'] = ['roles' => ['editor']];
        $token = $this->t->str($this->t->signIn('openid profile'), 'access_token');

        // Act
        $body = $this->t->json($this->call($token));

        // Assert
        self::assertSame(['editor'], $body['roles']);
    }

    public function testItNeverLetsTheProviderOverrideTheSubject(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn('openid email'), 'access_token');

        // Act
        $body = $this->t->json($this->call($token));

        // Assert
        self::assertSame('user-1', $body['sub']);
    }

    public function testItNeedsTheOpenidScope(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn('profile'), 'access_token');

        // Act
        $response = $this->call($token);

        // Assert
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', $this->t->json($response)['error']);
    }

    public function testItRefusesATokenThatIsNotForAPerson(): void
    {
        // Arrange
        $body = $this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']));

        // Act
        $response = $this->call($this->t->str($body, 'access_token'));

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItRefusesAPersonWhoNoLongerExists(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->claims->removed['user-1'] = true;

        // Act
        $response = $this->call($token);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItRefusesARequestThatDidNotPassThroughTheBearerMiddleware(): void
    {
        // Act
        $response = $this->t->server->userInfoHandler()->handle(new ServerRequest([], [], '/userinfo', 'GET'));

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    /** Runs the request through the bearer middleware and then the handler, as a router would. */
    private function call(string $token): ResponseInterface
    {
        $request = (new ServerRequest([], [], '/userinfo', 'GET'))->withHeader('Authorization', 'Bearer ' . $token);

        return $this->t->server->bearerTokenMiddleware()->process($request, $this->t->server->userInfoHandler());
    }
}
