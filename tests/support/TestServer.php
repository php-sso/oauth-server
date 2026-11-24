<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PhpSso\OAuthServer\AuthorizationServer;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Endpoint\AuthorizationHandler;
use PhpSso\OAuthServer\Endpoint\Endpoints;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\InMemory\InMemoryAuthorizationCodeStore;
use PhpSso\OAuthServer\InMemory\InMemoryClientRegistrations;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;
use PhpSso\OAuthServer\InMemory\InMemoryRefreshTokenStore;
use PhpSso\OAuthServer\InMemory\InMemoryRevokedAccessTokens;
use PhpSso\OAuthServer\InMemory\InMemorySessionRegistry;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Logout\LogoutSupport;
use PhpSso\OAuthServer\Pkce\Pkce;
use PhpSso\OAuthServer\Registration\ClientsWithRegistrations;
use Psr\Http\Message\ResponseInterface;

/**
 * A complete server for tests: in-memory stores, a frozen clock, and four registered clients.
 *
 *   web      confidential, authorization code + refresh, secret "s3cret"
 *   spa      public, authorization code + refresh
 *   service  confidential, client credentials, scope "api"
 *   tv       public, device code
 *   registrar confidential, client credentials, scope "client:register" (may register clients)
 */
final class TestServer
{
    public const ISSUER = 'https://sso.example.com';
    public const REDIRECT = 'https://app.example/cb';
    public const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    public readonly FrozenClock $clock;
    public readonly TestClientRepository $clients;
    public readonly InMemoryClientRegistrations $registrations;
    public readonly TestClaimsProvider $claims;
    public readonly TestAccessPolicy $policy;
    public readonly InMemoryAuthorizationCodeStore $codes;
    public readonly InMemoryRefreshTokenStore $refreshTokens;
    public readonly InMemoryDeviceAuthorizationStore $devices;
    public readonly InMemorySessionRegistry $sessions;
    public readonly InMemoryRevokedAccessTokens $revokedTokens;
    public readonly TestSessionTerminator $terminator;
    public readonly TestLogoutUi $logoutUi;
    public readonly FakeHttpClient $http;
    public readonly TestAuthorizationUi $authorizationUi;
    public readonly StaticKeyProvider $keys;
    public readonly AuthorizationServer $server;
    public readonly ServerConfig $config;

    public function __construct(bool $requirePkceForConfidentialClients = true, ?ErrorResponder $browserErrors = null, bool $registration = true)
    {
        $this->clock = new FrozenClock();
        $this->claims = new TestClaimsProvider();
        $this->policy = new TestAccessPolicy();
        $this->codes = new InMemoryAuthorizationCodeStore();
        $this->refreshTokens = new InMemoryRefreshTokenStore();
        $this->devices = new InMemoryDeviceAuthorizationStore();
        $this->sessions = new InMemorySessionRegistry();
        $this->revokedTokens = new InMemoryRevokedAccessTokens();
        $this->terminator = new TestSessionTerminator();
        $this->logoutUi = new TestLogoutUi();
        $this->http = new FakeHttpClient();
        $this->authorizationUi = new TestAuthorizationUi();
        $this->keys = new StaticKeyProvider(TestKeys::signingKey('key-1'));
        $this->config = new ServerConfig(self::ISSUER, ['openid', 'profile', 'email', 'api', 'client:register'], requirePkceForConfidentialClients: $requirePkceForConfidentialClients);

        $this->clients = new TestClientRepository();
        $this->registrations = new InMemoryClientRegistrations();
        $user = [GrantType::AuthorizationCode, GrantType::RefreshToken];
        $this->clients->add(new TestClient('web', [self::REDIRECT], true, $user, ['openid', 'profile', 'email'], 's3cret', 'https://app.example/backchannel-logout', ['https://app.example/signed-out']));
        $this->clients->add(new TestClient('spa', [self::REDIRECT], false, $user, ['openid', 'profile']));
        $this->clients->add(new TestClient('service', [], true, [GrantType::ClientCredentials], ['api'], 'svc-secret'));
        $this->clients->add(new TestClient('registrar', [], true, [GrantType::ClientCredentials], ['client:register'], 'reg-secret'));
        $this->clients->add(new TestClient('tv', [], false, [GrantType::DeviceCode, GrantType::RefreshToken], ['openid', 'profile']));

        $this->server = new AuthorizationServer(
            $this->config,
            new Endpoints(),
            new ClientsWithRegistrations($this->clients, $this->registrations),
            $this->claims,
            $this->policy,
            $this->authorizationUi,
            $this->keys,
            $this->codes,
            $this->refreshTokens,
            $this->devices,
            $this->revokedTokens,
            new LogoutSupport($this->sessions, $this->terminator, $this->logoutUi, $this->http, new RequestFactory()),
            new ResponseFactory(),
            new StreamFactory(),
            ['sub', 'name', 'email'],
            $this->clock,
            browserErrors: $browserErrors,
            registrations: $registration ? $this->registrations : null,
        );
    }

    /**
     * Sends an authorization request. Pass null as a value to leave that parameter out.
     *
     * @param array<string, string|null> $overrides
     */
    public function authorize(array $overrides = [], ?string $userId = 'user-1', ?string $sessionId = 'session-1', ?int $authTime = null, mixed $amr = null): ResponseInterface
    {
        $query = array_filter($overrides + [
            'response_type' => 'code',
            'client_id' => 'web',
            'redirect_uri' => self::REDIRECT,
            'scope' => 'openid profile',
            'state' => 'state-1',
            'nonce' => 'nonce-1',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
        ], static fn (?string $v): bool => $v !== null);

        $request = (new ServerRequest([], [], '/authorize', 'GET'))->withQueryParams($query);
        if ($userId !== null) {
            $request = $request->withAttribute(AuthorizationHandler::USER_ID, $userId);
        }
        if ($sessionId !== null) {
            $request = $request->withAttribute(AuthorizationHandler::SESSION_ID, $sessionId);
        }
        if ($authTime !== null) {
            $request = $request->withAttribute(AuthorizationHandler::AUTH_TIME, $authTime);
        }
        if ($amr !== null) {
            $request = $request->withAttribute(AuthorizationHandler::AMR, $amr);
        }

        return $this->server->authorizationHandler()->handle($request);
    }

    /** An access token that may register clients. */
    public function registrarToken(): string
    {
        return $this->str($this->json($this->token(['grant_type' => 'client_credentials', 'scope' => 'client:register'], ['registrar', 'reg-secret'])), 'access_token');
    }

    /**
     * Posts a registration request through the registration middleware, with the registrar's token unless another is given.
     *
     * @param array<string, mixed> $metadata
     */
    public function register(array $metadata, ?string $token = null): ResponseInterface
    {
        $request = (new ServerRequest([], [], '/register', 'POST'))
            ->withHeader('Authorization', 'Bearer ' . ($token ?? $this->registrarToken()))
            ->withParsedBody($metadata);

        return $this->server->registrationMiddleware()->process($request, $this->server->registrationHandler());
    }

    /**
     * Registers a client and returns the registration response body.
     *
     * @param array<string, mixed> $metadata
     *
     * @return array<string, mixed>
     */
    public function registered(array $metadata = ['redirect_uris' => [self::REDIRECT], 'token_endpoint_auth_method' => 'none']): array
    {
        return $this->json($this->register($metadata));
    }

    /**
     * Calls the client configuration endpoint (RFC 7592).
     *
     * @param array<string, mixed>|null $body
     */
    public function configure(string $method, string $clientId, ?string $token, ?array $body = null): ResponseInterface
    {
        $request = new ServerRequest([], [], 'https://sso.example.com/register/' . rawurlencode($clientId), $method);
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        if ($body !== null) {
            $request = $request->withParsedBody($body);
        }

        return $this->server->clientConfigurationHandler()->handle($request);
    }

    /** The authorization code from a successful authorization response. */
    public function codeFrom(ResponseInterface $response): string
    {
        return $this->query($response)['code'] ?? throw new \RuntimeException('No code in ' . $response->getHeaderLine('Location'));
    }

    /**
     * @param array<string, string> $form
     * @param array{string, string}|null $basic client id and secret for the Authorization header
     */
    public function token(array $form, ?array $basic = null): ResponseInterface
    {
        $request = (new ServerRequest([], [], '/token', 'POST'))->withParsedBody($form);
        if ($basic !== null) {
            $request = $request->withHeader('Authorization', 'Basic ' . base64_encode(urlencode($basic[0]) . ':' . urlencode($basic[1])));
        }

        return $this->server->tokenHandler()->handle($request);
    }

    /**
     * Runs the whole authorization code flow for the confidential client and returns the token response body.
     *
     * @return array<string, mixed>
     */
    public function signIn(string $scope = 'openid profile'): array
    {
        $code = $this->codeFrom($this->authorize(['scope' => $scope]));

        return $this->json($this->token([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::REDIRECT,
            'code_verifier' => self::VERIFIER,
        ], ['web', 's3cret']));
    }

    /** @return array<string, mixed> */
    public function json(ResponseInterface $response): array
    {
        $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        \assert(is_array($data));

        /** @var array<string, mixed> $data */
        return $data;
    }

    /**
     * A string field of a decoded JSON body, failing the test if it is missing or not a string.
     *
     * @param array<string, mixed> $data
     */
    public function str(array $data, string $key): string
    {
        $value = $data[$key] ?? null;
        \assert(is_string($value), "{$key} is not a string");

        return $value;
    }

    /** @return array<string, string> */
    public function query(ResponseInterface $response): array
    {
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);

        /** @var array<string, string> $query */
        return $query;
    }
}
