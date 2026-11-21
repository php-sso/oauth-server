<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\AuthorizationServer;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\AuthorizationServer;
use PhpSso\OAuthServer\Tests\Support\CapturingHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(AuthorizationServer::class, 'bearerTokenMiddleware')]
final class BearerTokenMiddlewareTest extends TestCase
{
    private TestServer $t;
    private CapturingHandler $next;

    protected function setUp(): void
    {
        $this->t = new TestServer();
        $this->next = new CapturingHandler();
    }

    public function testItAcceptsATokenIssuedToTheClientTheApiServes(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $middleware = $this->t->server->bearerTokenMiddleware([], 'web');

        // Act
        $response = $middleware->process($this->request($token), $this->next);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testItRefusesATokenIssuedToAnotherClient(): void
    {
        // Arrange
        $body = $this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']));
        $token = $this->t->str($body, 'access_token');
        $middleware = $this->t->server->bearerTokenMiddleware([], 'web');

        // Act
        $response = $middleware->process($this->request($token), $this->next);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItAcceptsTheServersOwnAudienceWhenNoAudienceIsGiven(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $middleware = $this->t->server->bearerTokenMiddleware();

        // Act
        $response = $middleware->process($this->request($token), $this->next);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    private function request(string $token): ServerRequest
    {
        return (new ServerRequest([], [], '/api', 'GET'))->withHeader('Authorization', 'Bearer ' . $token);
    }
}
