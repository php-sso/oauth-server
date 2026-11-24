<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\ClientRegistrationHandler;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Stream;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\ClientRegistrationHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(ClientRegistrationHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testItRegistersAPublicClient(): void
    {
        // Act
        $response = $this->t->register(['redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'client_name' => 'My MCP client']);

        // Assert
        $body = $this->t->json($response);
        self::assertSame(201, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame([TestServer::REDIRECT], $body['redirect_uris']);
        self::assertSame('My MCP client', $body['client_name']);
        self::assertSame('none', $body['token_endpoint_auth_method']);
        self::assertSame(['authorization_code'], $body['grant_types']);
        self::assertSame(['code'], $body['response_types']);
        self::assertSame('openid', $body['scope']);
        self::assertArrayNotHasKey('client_secret', $body);
        self::assertSame('https://sso.example.com/register/' . $this->t->str($body, 'client_id'), $body['registration_client_uri']);
        self::assertNotSame('', $this->t->str($body, 'registration_access_token'));
        self::assertIsInt($body['client_id_issued_at']);
    }

    public function testItIssuesASecretToAConfidentialClientAndStoresOnlyItsHash(): void
    {
        // Act
        $body = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT]]);

        // Assert
        $secret = $this->t->str($body, 'client_secret');
        $stored = $this->t->registrations->find($this->t->str($body, 'client_id'));
        self::assertSame('client_secret_basic', $body['token_endpoint_auth_method']);
        self::assertSame(0, $body['client_secret_expires_at']);
        self::assertNotNull($stored);
        self::assertNotSame($secret, $stored->secretHash);
        self::assertTrue($stored->verifySecret($secret));
        self::assertSame('registrar', $stored->registeredBy);
    }

    public function testARegisteredClientCanSignPeopleIn(): void
    {
        // Arrange
        $body = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'scope' => 'openid profile']);
        $clientId = $this->t->str($body, 'client_id');

        // Act
        $code = $this->t->codeFrom($this->t->authorize(['client_id' => $clientId]));
        $tokens = $this->t->token([
            'grant_type' => 'authorization_code', 'client_id' => $clientId, 'code' => $code,
            'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER,
        ]);

        // Assert
        self::assertSame(200, $tokens->getStatusCode());
    }

    public function testItReadsAJsonBodyThatTheFrameworkDidNotParse(): void
    {
        // Arrange
        $stream = new Stream('php://memory', 'wb+');
        $stream->write('{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}');
        $request = (new ServerRequest([], [], '/register', 'POST'))
            ->withHeader('Authorization', 'Bearer ' . $this->t->registrarToken())
            ->withBody($stream);

        // Act
        $response = $this->t->server->registrationMiddleware()->process($request, $this->t->server->registrationHandler());

        // Assert
        self::assertSame(201, $response->getStatusCode());
    }

    public function testItNeedsAnAccessToken(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/register', 'POST'))->withParsedBody(['redirect_uris' => [TestServer::REDIRECT]]);

        // Act
        $response = $this->t->server->registrationMiddleware()->process($request, $this->t->server->registrationHandler());

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', $this->t->json($response)['error']);
    }

    public function testATokenWithoutTheRegistrationScopeIsRefused(): void
    {
        // Arrange
        $token = $this->t->str($this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret'])), 'access_token');

        // Act
        $response = $this->t->register(['redirect_uris' => [TestServer::REDIRECT]], $token);

        // Assert
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('insufficient_scope', $this->t->json($response)['error']);
    }

    public function testItRefusesToRunWithoutTheMiddleware(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/register', 'POST'))->withParsedBody(['redirect_uris' => [TestServer::REDIRECT]]);

        // Act
        $response = $this->t->server->registrationHandler()->handle($request);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItOnlyAcceptsPost(): void
    {
        // Act
        $response = $this->t->server->registrationHandler()->handle(new ServerRequest([], [], '/register', 'GET'));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testTheBodyMustBeAJsonObject(): void
    {
        // Arrange
        $stream = new Stream('php://memory', 'wb+');
        $stream->write('[1,2]');
        $request = (new ServerRequest([], [], '/register', 'POST'))
            ->withHeader('Authorization', 'Bearer ' . $this->t->registrarToken())
            ->withBody($stream);

        // Act
        $response = $this->t->server->registrationMiddleware()->process($request, $this->t->server->registrationHandler());

        // Assert
        self::assertSame('invalid_client_metadata', $this->t->json($response)['error']);
    }

    public function testItRefusesASoftwareStatement(): void
    {
        // Act
        $response = $this->t->register(['redirect_uris' => [TestServer::REDIRECT], 'software_statement' => 'eyJ.x.y']);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_software_statement', $this->t->json($response)['error']);
    }
}
