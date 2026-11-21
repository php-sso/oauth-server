<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Middleware\BearerTokenMiddleware;

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Http\JsonErrorResponder;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Middleware\BearerTokenMiddleware;
use PhpSso\OAuthServer\Tests\Support\CapturingHandler;
use PhpSso\OAuthServer\Tests\Support\JwtForge;
use PhpSso\OAuthServer\Tests\Support\TestKeys;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(BearerTokenMiddleware::class, 'process')]
final class ProcessTest extends TestCase
{
    private TestServer $t;
    private CapturingHandler $next;

    protected function setUp(): void
    {
        $this->t = new TestServer();
        $this->next = new CapturingHandler();
    }

    public function testItLetsAValidAccessTokenThroughAndExposesWhoItIsFor(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');

        // Act
        $response = $this->send($token);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        $request = $this->next->request;
        self::assertNotNull($request);
        self::assertSame('user-1', $request->getAttribute(BearerTokenMiddleware::USER_ID));
        self::assertSame('web', $request->getAttribute(BearerTokenMiddleware::CLIENT_ID));
        self::assertSame(['openid', 'profile'], $request->getAttribute(BearerTokenMiddleware::SCOPES));
        self::assertSame('authorization_code', $request->getAttribute(BearerTokenMiddleware::GRANT_TYPE));
        self::assertSame('session-1', $request->getAttribute(BearerTokenMiddleware::SESSION_ID));
        self::assertIsString($request->getAttribute(BearerTokenMiddleware::TOKEN_ID));
    }

    public function testAClientCredentialsTokenHasNoUser(): void
    {
        // Arrange
        $body = $this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']));

        // Act
        $response = $this->send($this->t->str($body, 'access_token'));

        // Assert
        self::assertSame(200, $response->getStatusCode());
        $request = $this->next->request;
        self::assertNotNull($request);
        self::assertNull($request->getAttribute(BearerTokenMiddleware::USER_ID));
        self::assertSame('service', $request->getAttribute(BearerTokenMiddleware::CLIENT_ID));
    }

    public function testItRefusesARequestWithoutAToken(): void
    {
        // Act
        $response = $this->send(null);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertNull($this->next->request);
        self::assertStringStartsWith('Bearer', $response->getHeaderLine('WWW-Authenticate'));
    }

    #[DataProvider('garbage')]
    public function testItRefusesTokensThatAreNotTokens(string $header): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/api', 'GET'))->withHeader('Authorization', $header);

        // Act
        $response = $this->t->server->bearerTokenMiddleware()->process($request, $this->next);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertNull($this->next->request);
    }

    /** @return array<string, array{string}> */
    public static function garbage(): array
    {
        return [
            'basic auth' => ['Basic dXNlcjpwYXNz'],
            'not a jwt' => ['Bearer abc'],
            'two parts' => ['Bearer abc.def'],
            'extra words' => ['Bearer abc def'],
            'empty token' => ['Bearer '],
        ];
    }

    public function testItRefusesAnIdTokenUsedAsAnAccessToken(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $response = $this->send($idToken);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertNull($this->next->request);
    }

    public function testItRefusesAnExpiredToken(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->clock->advance(3600 + 31);

        // Act
        $response = $this->send($token);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItRefusesATokenSignedWithAnotherKey(): void
    {
        // Arrange
        $forged = JwtForge::rs256(['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => 'key-1'], [
            'iss' => TestServer::ISSUER, 'sub' => 'admin', 'aud' => TestServer::ISSUER, 'client_id' => 'web', 'scope' => 'openid',
            'jti' => 'x', 'gty' => 'authorization_code', 'exp' => $this->t->clock->timestamp() + 60,
        ], TestKeys::privatePem('b'));

        // Act
        $response = $this->send($forged);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItRefusesATokenForAnotherAudience(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $middleware = new BearerTokenMiddleware(
            new JwtDecoder($this->t->keys),
            new ClaimsValidator($this->t->clock, TestServer::ISSUER),
            new JsonErrorResponder(new Responses(new ResponseFactory(), new StreamFactory())),
            'https://some-other-api.example',
            $this->t->refreshTokens,
            $this->t->revokedTokens,
        );

        // Act
        $response = $middleware->process($this->request($token), $this->next);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItRefusesATokenWhoseFamilyWasRevoked(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->refreshTokens->revokeSession('session-1', $this->t->clock->timestamp());

        // Act
        $response = $this->send($token);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertNull($this->next->request);
    }

    public function testItRefusesATokenThatLacksARequiredScopeWith403(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn('openid'), 'access_token');
        $middleware = $this->t->server->bearerTokenMiddleware(['profile']);

        // Act
        $response = $middleware->process($this->request($token), $this->next);

        // Assert
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', $this->t->json($response)['error']);
    }

    public function testItDoesNotExplainWhichCheckFailed(): void
    {
        // Arrange
        $token = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->clock->advance(7200);

        // Act
        $expired = $this->t->json($this->send($token));
        $garbage = $this->t->json($this->send('abc'));

        // Assert
        self::assertSame('The access token is not valid.', $expired['error_description']);
        self::assertSame('The access token is not valid.', $garbage['error_description']);
    }

    private function request(?string $token): ServerRequest
    {
        $request = new ServerRequest([], [], '/api', 'GET');

        return $token === null ? $request : $request->withHeader('Authorization', 'Bearer ' . $token);
    }

    private function send(?string $token): ResponseInterface
    {
        return $this->t->server->bearerTokenMiddleware()->process($this->request($token), $this->next);
    }
}
