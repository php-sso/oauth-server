<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\RevocationHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\RevocationHandler;
use PhpSso\OAuthServer\Tests\Support\CapturingHandler;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(RevocationHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testRevokingARefreshTokenRevokesTheWholeSignIn(): void
    {
        // Arrange
        $tokens = $this->t->signIn();

        // Act
        $response = $this->revoke($this->t->str($tokens, 'refresh_token'));

        // Assert
        self::assertSame(200, $response->getStatusCode());
        $refresh = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);
        self::assertSame('invalid_grant', $this->t->json($refresh)['error']);
        self::assertSame(401, $this->callApi($this->t->str($tokens, 'access_token'))->getStatusCode());
    }

    public function testRevokingAnAccessTokenRevokesOnlyThatToken(): void
    {
        // Arrange
        $tokens = $this->t->signIn();

        // Act
        $response = $this->revoke($this->t->str($tokens, 'access_token'));

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(401, $this->callApi($this->t->str($tokens, 'access_token'))->getStatusCode());
        $refresh = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);
        self::assertSame(200, $refresh->getStatusCode());
    }

    public function testItAnswersOkForATokenItDoesNotKnow(): void
    {
        // Act
        $response = $this->revoke('made-up-token');

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testItIgnoresATokenThatBelongsToAnotherClient(): void
    {
        // Arrange
        $tokens = $this->t->signIn();
        $this->t->clients->add(new TestClient('other', [], true, [], [], 'o'));

        // Act
        $response = $this->t->server->revocationHandler()->handle($this->request(['token' => $this->t->str($tokens, 'refresh_token')], ['other', 'o']));

        // Assert
        self::assertSame(200, $response->getStatusCode());
        $refresh = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);
        self::assertSame(200, $refresh->getStatusCode());
    }

    public function testTheClientMustAuthenticate(): void
    {
        // Arrange
        $tokens = $this->t->signIn();

        // Act
        $response = $this->t->server->revocationHandler()->handle($this->request(['token' => $this->t->str($tokens, 'refresh_token')], ['web', 'wrong']));

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', $this->t->json($response)['error']);
    }

    public function testItNeedsAToken(): void
    {
        // Act
        $response = $this->t->server->revocationHandler()->handle($this->request([], ['web', 's3cret']));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testItOnlyAcceptsPost(): void
    {
        // Act
        $response = $this->t->server->revocationHandler()->handle(new ServerRequest([], [], '/revoke', 'GET'));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testAClientCredentialsTokenCanBeRevokedWhenAStoreIsConfigured(): void
    {
        // Arrange
        $body = $this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']));
        $access = $this->t->str($body, 'access_token');

        // Act
        $response = $this->t->server->revocationHandler()->handle($this->request(['token' => $access], ['service', 'svc-secret']));

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame(401, $this->callApi($access)->getStatusCode());
    }

    /**
     * @param array<string, string> $form
     * @param array{string, string} $basic
     */
    private function request(array $form, array $basic): ServerRequest
    {
        return (new ServerRequest([], [], '/revoke', 'POST'))
            ->withHeader('Authorization', 'Basic ' . base64_encode($basic[0] . ':' . $basic[1]))
            ->withParsedBody($form);
    }

    private function revoke(string $token): ResponseInterface
    {
        return $this->t->server->revocationHandler()->handle($this->request(['token' => $token], ['web', 's3cret']));
    }

    private function callApi(string $accessToken): ResponseInterface
    {
        $request = (new ServerRequest([], [], '/api', 'GET'))->withHeader('Authorization', 'Bearer ' . $accessToken);

        return $this->t->server->bearerTokenMiddleware()->process($request, new CapturingHandler());
    }
}
