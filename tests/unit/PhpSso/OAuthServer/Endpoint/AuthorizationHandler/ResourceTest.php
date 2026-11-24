<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\AuthorizationHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\AuthorizationHandler;
use PhpSso\OAuthServer\Pkce\Pkce;
use PhpSso\OAuthServer\Tests\Support\TestResourcePolicy;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Token\TokenHash;

/** Resource indicators (RFC 8707) at the authorization endpoint. */
#[CoversMethod(AuthorizationHandler::class, 'handle')]
final class ResourceTest extends TestCase
{
    private function server(): TestServer
    {
        return new TestServer(resourcePolicy: new TestResourcePolicy(['web' => ['https://mcp.example/', 'https://files.example/api']]));
    }

    /** A GET request the way PHP builds it: the raw query, and the parameters with the last value of a repeated one. */
    private function request(string $query): ServerRequest
    {
        parse_str($query, $parameters);

        /** @var array<string, mixed> $parameters */
        return (new ServerRequest([], [], 'https://sso.example.com/authorize?' . $query, 'GET'))->withQueryParams($parameters);
    }

    public function testTheResourcesAreKeptWithTheCode(): void
    {
        // Arrange
        $t = $this->server();

        // Act
        $response = $t->authorize(['resource' => 'https://mcp.example/']);

        // Assert
        $record = $t->codes->find(TokenHash::of($t->codeFrom($response)));
        self::assertSame(['https://mcp.example/'], $record?->resources);
    }

    public function testSeveralResourcesCanBeRepeated(): void
    {
        // Arrange
        $t = $this->server();
        $query = http_build_query([
            'response_type' => 'code', 'client_id' => 'web', 'redirect_uri' => TestServer::REDIRECT, 'scope' => 'openid', 'state' => 's',
            'code_challenge' => Pkce::challengeFor(TestServer::VERIFIER), 'code_challenge_method' => 'S256',
        ]) . '&resource=' . rawurlencode('https://mcp.example/') . '&resource=' . rawurlencode('https://files.example/api');
        $request = $this->request($query)->withAttribute(AuthorizationHandler::USER_ID, 'user-1');

        // Act
        $response = $t->server->authorizationHandler()->handle($request);

        // Assert
        $record = $t->codes->find(TokenHash::of($t->codeFrom($response)));
        self::assertSame(['https://mcp.example/', 'https://files.example/api'], $record?->resources);
    }

    public function testAResourceTheClientMayNotHaveIsAnInvalidTargetError(): void
    {
        // Arrange
        $t = $this->server();

        // Act
        $response = $t->authorize(['resource' => 'https://evil.example/']);

        // Assert
        self::assertSame('invalid_target', $t->query($response)['error']);
        self::assertSame('state-1', $t->query($response)['state']);
    }

    public function testAMalformedResourceIsAnInvalidTargetError(): void
    {
        // Arrange
        $t = $this->server();

        // Act
        $response = $t->authorize(['resource' => 'https://mcp.example/#fragment']);

        // Assert
        self::assertSame('invalid_target', $t->query($response)['error']);
    }

    public function testTheParameterIsIgnoredWithoutAPolicy(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $response = $t->authorize(['resource' => 'https://anything.example/']);

        // Assert
        $record = $t->codes->find(TokenHash::of($t->codeFrom($response)));
        self::assertSame([], $record?->resources);
    }

    public function testSeveralResourcesSurviveASignInRedirect(): void
    {
        // Arrange
        $t = $this->server();
        $query = http_build_query(['response_type' => 'code', 'client_id' => 'web', 'redirect_uri' => TestServer::REDIRECT, 'scope' => 'openid', 'code_challenge' => Pkce::challengeFor(TestServer::VERIFIER), 'code_challenge_method' => 'S256'])
            . '&resource=' . rawurlencode('https://mcp.example/') . '&resource=' . rawurlencode('https://files.example/api');
        $request = $this->request($query);

        // Act
        $t->server->authorizationHandler()->handle($request);

        // Assert
        $resume = $t->authorizationUi->loginRequest?->getAttribute(AuthorizationHandler::RESUME_PARAMS);
        self::assertIsArray($resume);
        self::assertSame(['https://mcp.example/', 'https://files.example/api'], $resume['resource'] ?? null);
    }
}
