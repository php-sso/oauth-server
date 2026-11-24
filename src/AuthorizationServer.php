<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer;

use PhpSso\OAuthServer\Authorization\AccessPolicy;
use PhpSso\OAuthServer\Authorization\AuthorizationUi;
use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Authorization\UserClaimsProvider;
use PhpSso\OAuthServer\Clock\SystemClock;
use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Device\DeviceVerifier;
use PhpSso\OAuthServer\Endpoint\AuthorizationHandler;
use PhpSso\OAuthServer\Endpoint\ClientConfigurationHandler;
use PhpSso\OAuthServer\Endpoint\ClientRegistrationHandler;
use PhpSso\OAuthServer\Endpoint\DeviceAuthorizationHandler;
use PhpSso\OAuthServer\Endpoint\DiscoveryHandler;
use PhpSso\OAuthServer\Endpoint\EndSessionHandler;
use PhpSso\OAuthServer\Endpoint\Endpoints;
use PhpSso\OAuthServer\Endpoint\IntrospectionHandler;
use PhpSso\OAuthServer\Endpoint\JwksHandler;
use PhpSso\OAuthServer\Endpoint\RevocationHandler;
use PhpSso\OAuthServer\Endpoint\TokenHandler;
use PhpSso\OAuthServer\Endpoint\UserInfoHandler;
use PhpSso\OAuthServer\Grant\AuthorizationCodeStore;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationStore;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use PhpSso\OAuthServer\Grant\RevokedAccessTokens;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\JsonErrorResponder;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use PhpSso\OAuthServer\Jwt\KeyProvider;
use PhpSso\OAuthServer\Logout\BackchannelLogout;
use PhpSso\OAuthServer\Logout\LogoutService;
use PhpSso\OAuthServer\Logout\LogoutSupport;
use PhpSso\OAuthServer\Middleware\BearerTokenMiddleware;
use PhpSso\OAuthServer\Registration\ClientMetadataValidator;
use PhpSso\OAuthServer\Registration\ClientRegistrations;
use PhpSso\OAuthServer\Registration\RegistrarPolicy;
use PhpSso\OAuthServer\Resource\ResourceIndicators;
use PhpSso\OAuthServer\Resource\ResourcePolicy;
use PhpSso\OAuthServer\Registration\RegistrationConfig;
use PhpSso\OAuthServer\Token\RandomTokenGenerator;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;
use PhpSso\OAuthServer\Token\AccessTokenVerifier;
use PhpSso\OAuthServer\Token\TokenGenerator;
use PhpSso\OAuthServer\Token\TokenIssuer;
use PhpSso\OAuthServer\Token\UserCodeGenerator;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Wires the endpoints together. Give it your implementations of the interfaces (every collaborator is
 * required: a missing one is an error at construction, not a feature that quietly switches off), then mount
 * the handlers on your router:
 *
 *   $server = new AuthorizationServer(...);
 *   $router->get('/authorize', $server->authorizationHandler());
 *   $router->post('/token', $server->tokenHandler());
 *   $router->get('/userinfo', $server->userInfoHandler(), $server->bearerTokenMiddleware(['openid']));
 *
 * Every handler is also a plain class you can construct yourself.
 */
final readonly class AuthorizationServer
{
    private ClockInterface $clock;
    private TokenGenerator $tokenGenerator;
    private UserCodeGenerator $userCodeGenerator;
    private Responses $responses;
    private ErrorResponder $errors;
    private ErrorResponder $browserErrors;
    private ScopeValidator $scopes;
    private ClientAuthenticator $clientAuthenticator;
    private ResourceIndicators $resources;
    private TokenIssuer $issuer;
    private JwtDecoder $decoder;
    private StreamFactoryInterface $streamFactory;

    /**
     * @param list<string> $claimNames    The claims your UserClaimsProvider can release, for the discovery document.
     * @param ErrorResponder|null $errors        Answers the errors of the API endpoints (token, userinfo, introspection...): JSON by default.
     * @param ErrorResponder|null $browserErrors Answers the errors of the two endpoints a person's browser lands on, the
     *                                           authorization and end-session endpoints, such as an unregistered redirect URI.
     *                                           Give it a responder that shows a page; the one for `$errors` when null.
     * @param ClientRegistrations|null $registrations Turns on dynamic client registration (RFC 7591 and 7592) when given. Your
     *                                           ClientRepository must find these clients too: see ClientsWithRegistrations.
     * @param RegistrationConfig|null $registration What registration accepts; the defaults when null.
     * @param ResourcePolicy|null $resourcePolicy Turns on resource indicators (RFC 8707): which resources a client may get tokens for. The `resource` parameter is ignored without one.
     * @param RegistrarPolicy|null $registrarPolicy Which clients may register, and what the apps they register may get, per registrar.
     */
    public function __construct(
        private ServerConfig $config,
        private Endpoints $endpoints,
        private ClientRepository $clients,
        private UserClaimsProvider $claims,
        private AccessPolicy $policy,
        private AuthorizationUi $ui,
        private KeyProvider $keys,
        private AuthorizationCodeStore $codes,
        private RefreshTokenStore $refreshTokens,
        private DeviceAuthorizationStore $devices,
        private RevokedAccessTokens $revokedAccessTokens,
        private LogoutSupport $logout,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory,
        private array $claimNames,
        ?ClockInterface $clock = null,
        ?TokenGenerator $tokenGenerator = null,
        ?UserCodeGenerator $userCodeGenerator = null,
        ?ErrorResponder $errors = null,
        ?ErrorResponder $browserErrors = null,
        private ?ClientRegistrations $registrations = null,
        private ?RegistrationConfig $registration = null,
        private ?RegistrarPolicy $registrarPolicy = null,
        ?ResourcePolicy $resourcePolicy = null,
    ) {
        $this->clock = $clock ?? new SystemClock();
        $this->tokenGenerator = $tokenGenerator ?? new RandomTokenGenerator();
        $this->userCodeGenerator = $userCodeGenerator ?? new RandomUserCodeGenerator();
        $this->streamFactory = $streamFactory;
        $this->responses = new Responses($responseFactory, $streamFactory);
        $this->errors = $errors ?? new JsonErrorResponder($this->responses);
        $this->browserErrors = $browserErrors ?? $this->errors;
        $this->scopes = new ScopeValidator($config);
        $this->resources = new ResourceIndicators($resourcePolicy);
        $this->clientAuthenticator = new ClientAuthenticator($clients);
        $this->decoder = new JwtDecoder($keys);
        $this->issuer = new TokenIssuer($config, new JwtEncoder($keys), $this->tokenGenerator, $refreshTokens, $claims, $this->clock);
    }

    public function authorizationHandler(): AuthorizationHandler
    {
        return new AuthorizationHandler(
            $this->config, $this->clients, $this->scopes, $this->policy, $this->ui, $this->codes,
            $this->tokenGenerator, $this->clock, $this->responses, $this->browserErrors, $this->logout->sessions, $this->resources,
        );
    }

    public function tokenHandler(): TokenHandler
    {
        return new TokenHandler(
            $this->clientAuthenticator, $this->scopes, $this->codes, $this->refreshTokens, $this->devices,
            $this->policy, $this->issuer, $this->clock, $this->responses, $this->errors, $this->resources,
        );
    }

    public function deviceAuthorizationHandler(): DeviceAuthorizationHandler
    {
        return new DeviceAuthorizationHandler(
            $this->config, $this->endpoints, $this->clientAuthenticator, $this->scopes, $this->devices,
            $this->tokenGenerator, $this->userCodeGenerator, $this->clock, $this->responses, $this->errors,
        );
    }

    /** For your device verification page: look up the code a person typed, then approve or deny it. */
    public function deviceVerifier(): DeviceVerifier
    {
        return new DeviceVerifier($this->devices, $this->clients, $this->policy, $this->clock);
    }

    /**
     * What to call whenever a login session ends: revokes its tokens and tells the clients that took part.
     * Call it from your own code when you end a session yourself (the person signed out, an administrator
     * ended it, a password was reset); the end-session endpoint calls it for you.
     */
    public function logoutService(): LogoutService
    {
        return new LogoutService(
            $this->refreshTokens,
            new BackchannelLogout(
                $this->config, $this->clients, $this->logout->sessions, new JwtEncoder($this->keys), $this->tokenGenerator,
                $this->clock, $this->logout->httpClient, $this->logout->requestFactory, $this->streamFactory,
            ),
            $this->clock,
        );
    }

    /** The end-session endpoint (OpenID Connect RP-Initiated Logout). */
    public function endSessionHandler(): EndSessionHandler
    {
        return new EndSessionHandler(
            $this->config, $this->clients, $this->decoder, $this->logout->terminator, $this->logoutService(), $this->logout->ui, $this->browserErrors,
        );
    }

    /** RFC 7009. */
    public function revocationHandler(): RevocationHandler
    {
        return new RevocationHandler(
            $this->clientAuthenticator, $this->refreshTokens, $this->accessTokenVerifier(), $this->clock,
            $this->responses, $this->errors, $this->revokedAccessTokens,
        );
    }

    /** RFC 7662. */
    public function introspectionHandler(): IntrospectionHandler
    {
        return new IntrospectionHandler(
            $this->clientAuthenticator, $this->refreshTokens, $this->accessTokenVerifier(), $this->clock,
            $this->responses, $this->errors,
        );
    }

    /** RFC 7591: mount on POST, behind {@see self::registrationMiddleware()}. */
    public function registrationHandler(): ClientRegistrationHandler
    {
        return new ClientRegistrationHandler(
            $this->config, $this->endpoints, $this->registrationValidator(), $this->registrationStore(),
            $this->tokenGenerator, $this->clock, $this->responses, $this->errors, $this->registrarPolicy,
        );
    }

    /** RFC 7592: mount on GET, PUT and DELETE of `{registration endpoint}/{client_id}`. It checks the registration access token itself. */
    public function clientConfigurationHandler(): ClientConfigurationHandler
    {
        return new ClientConfigurationHandler(
            $this->config, $this->endpoints, $this->registrationValidator(), $this->registrationStore(),
            $this->tokenGenerator, $this->responses, $this->errors, $this->registrarPolicy,
        );
    }

    /** Only an access token with the registration scope gets through; hand that scope to the clients you trust to register others. */
    public function registrationMiddleware(): BearerTokenMiddleware
    {
        $this->registrationStore();

        return $this->bearerTokenMiddleware([($this->registration ?? new RegistrationConfig())->scope]);
    }

    private function registrationValidator(): ClientMetadataValidator
    {
        return new ClientMetadataValidator($this->config, $this->registration ?? new RegistrationConfig());
    }

    private function registrationStore(): ClientRegistrations
    {
        return $this->registrations ?? throw new \LogicException('Dynamic client registration is off: pass a ClientRegistrations to the AuthorizationServer.');
    }

    private function accessTokenVerifier(): AccessTokenVerifier
    {
        return new AccessTokenVerifier(
            $this->decoder,
            new ClaimsValidator($this->clock, $this->config->issuer),
            $this->config->audience(),
            $this->refreshTokens,
            $this->revokedAccessTokens,
        );
    }

    public function userInfoHandler(): UserInfoHandler
    {
        return new UserInfoHandler($this->claims, $this->responses, $this->errors);
    }

    public function jwksHandler(): JwksHandler
    {
        return new JwksHandler($this->keys, $this->responses);
    }

    public function discoveryHandler(): DiscoveryHandler
    {
        return new DiscoveryHandler($this->config, $this->endpoints, $this->responses, $this->claimNames, $this->registrations !== null && ($this->registrarPolicy === null || $this->registrarPolicy->anyRegistrar()));
    }

    /**
     * Protects a route with an access token issued by this server.
     *
     * @param list<string> $requiredScopes
     * @param string|null  $audience       The `aud` the route accepts. An API that serves one application passes that
     *                                     application's client id, so tokens issued to other applications are refused;
     *                                     the server's own audience when null (for the server's own endpoints).
     */
    public function bearerTokenMiddleware(array $requiredScopes = [], ?string $audience = null): BearerTokenMiddleware
    {
        return new BearerTokenMiddleware(
            $this->decoder,
            new ClaimsValidator($this->clock, $this->config->issuer),
            $this->errors,
            $audience ?? $this->config->audience(),
            $this->refreshTokens,
            $this->revokedAccessTokens,
            $requiredScopes,
        );
    }
}
