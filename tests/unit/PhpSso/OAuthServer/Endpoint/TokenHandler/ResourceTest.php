<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\TokenHandler;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\TokenHandler;
use PhpSso\OAuthServer\Tests\Support\TestResourcePolicy;
use PhpSso\OAuthServer\Tests\Support\TestServer;

/** Resource indicators (RFC 8707) at the token endpoint: what the audience of the access token becomes. */
#[CoversMethod(TokenHandler::class, 'handle')]
final class ResourceTest extends TestCase
{
    private const MCP = 'https://mcp.example/';
    private const FILES = 'https://files.example/api';

    private TestResourcePolicy $policy;
    private TestServer $t;

    protected function setUp(): void
    {
        $this->policy = new TestResourcePolicy(['web' => [self::MCP, self::FILES], 'service' => [self::MCP]]);
        $this->t = new TestServer(resourcePolicy: $this->policy);
    }

    /**
     * @param array<string, string|null> $authorize
     * @param array<string, string>      $token
     *
     * @return array<string, mixed>
     */
    private function signIn(array $authorize = [], array $token = []): array
    {
        $code = $this->t->codeFrom($this->t->authorize($authorize));

        return $this->t->json($this->t->token($token + [
            'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER,
        ], ['web', 's3cret']));
    }

    /** @return array<string, mixed> */
    private function claims(string $jwt): array
    {
        $payload = json_decode((string) base64_decode(strtr(explode('.', $jwt)[1], '-_', '+/'), true), true, 512, JSON_THROW_ON_ERROR);
        \assert(is_array($payload));

        /** @var array<string, mixed> $payload */
        return $payload;
    }

    /** @param array<string, mixed> $tokens */
    private function audience(array $tokens): mixed
    {
        return $this->claims($this->t->str($tokens, 'access_token'))['aud'];
    }

    public function testTheAccessTokenIsForTheResourceAndThisServerButNotTheClient(): void
    {
        // Act
        $tokens = $this->signIn(['resource' => self::MCP]);

        // Assert
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($tokens));
    }

    public function testWithoutAResourceTheAudienceIsAsItAlwaysWas(): void
    {
        // Act
        $tokens = $this->signIn();

        // Assert
        self::assertSame([TestServer::ISSUER, 'web'], $this->audience($tokens));
    }

    public function testTheIdTokenIsStillForTheClient(): void
    {
        // Act
        $tokens = $this->signIn(['resource' => self::MCP]);

        // Assert
        self::assertSame('web', $this->claims($this->t->str($tokens, 'id_token'))['aud']);
    }

    public function testTheTokenRequestMayNarrowTheResources(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize(['resource' => self::MCP]));

        // Act
        $tokens = $this->t->json($this->t->token([
            'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER, 'resource' => self::MCP,
        ], ['web', 's3cret']));

        // Assert
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($tokens));
    }

    public function testTheTokenRequestMayNotAddAResourceTheAuthorizationDidNotName(): void
    {
        // Act
        $response = $this->t->token([
            'grant_type' => 'authorization_code', 'code' => $this->t->codeFrom($this->t->authorize(['resource' => self::MCP])),
            'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER, 'resource' => self::FILES,
        ], ['web', 's3cret']);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_target', $this->t->json($response)['error']);
    }

    public function testTheTokenRequestMayNameAResourceWhenTheAuthorizationNamedNone(): void
    {
        // Act
        $tokens = $this->signIn([], ['resource' => self::FILES]);

        // Assert
        self::assertSame([self::FILES, TestServer::ISSUER], $this->audience($tokens));
    }

    public function testARefreshKeepsTheResources(): void
    {
        // Arrange
        $tokens = $this->signIn(['resource' => self::MCP]);

        // Act
        $refreshed = $this->t->json($this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']));

        // Assert
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($refreshed));
    }

    public function testARefreshThatNarrowsDoesNotLoseTheRestOfTheGrant(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize(['resource' => self::MCP]));
        $tokens = $this->t->json($this->t->token([
            'grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER,
        ], ['web', 's3cret']));
        $this->policy->allowed['web'] = [self::MCP];

        // Act
        $again = $this->t->json($this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token'), 'resource' => self::MCP], ['web', 's3cret']));
        $third = $this->t->json($this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($again, 'refresh_token')], ['web', 's3cret']));

        // Assert
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($again));
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($third));
    }

    public function testARefreshCannotAddAResource(): void
    {
        // Arrange
        $tokens = $this->signIn(['resource' => self::MCP]);

        // Act
        $response = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token'), 'resource' => self::FILES], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_target', $this->t->json($response)['error']);
    }

    public function testARefreshIsRefusedOnceTheClientLostTheResourceAndTheTokenIsNotSpent(): void
    {
        // Arrange
        $tokens = $this->signIn(['resource' => self::MCP]);
        $this->policy->allowed['web'] = [];

        // Act
        $refused = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);
        $this->policy->allowed['web'] = [self::MCP];
        $retry = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_target', $this->t->json($refused)['error']);
        self::assertSame(200, $retry->getStatusCode());
    }

    public function testClientCredentialsCanAskForAResource(): void
    {
        // Act
        $tokens = $this->t->json($this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api', 'resource' => self::MCP], ['service', 'svc-secret']));

        // Assert
        self::assertSame([self::MCP, TestServer::ISSUER], $this->audience($tokens));
    }

    public function testClientCredentialsCannotAskForAResourceItMayNotHave(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api', 'resource' => self::FILES], ['service', 'svc-secret']);

        // Assert
        self::assertSame('invalid_target', $this->t->json($response)['error']);
    }

    public function testAnApiThatChecksItsOwnResourceAcceptsOnlyTokensForIt(): void
    {
        // Arrange
        $forMcp = $this->signIn(['resource' => self::MCP]);
        $forFiles = $this->signIn(['resource' => self::FILES]);
        $middleware = $this->t->server->bearerTokenMiddleware(['openid'], audience: self::MCP);
        $call = static fn (string $token): int => $middleware->process(
            (new \Laminas\Diactoros\ServerRequest([], [], '/api'))->withHeader('Authorization', 'Bearer ' . $token),
            new \PhpSso\OAuthServer\Tests\Support\CapturingHandler(),
        )->getStatusCode();

        // Act
        $results = [$call($this->t->str($forMcp, 'access_token')), $call($this->t->str($forFiles, 'access_token'))];

        // Assert
        self::assertSame([200, 401], $results);
    }
}
