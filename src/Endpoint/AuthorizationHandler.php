<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Authorization\AccessPolicy;
use PhpSso\OAuthServer\Authorization\AuthorizationRequest;
use PhpSso\OAuthServer\Authorization\AuthorizationUi;
use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\AuthorizationCodeRecord;
use PhpSso\OAuthServer\Grant\AuthorizationCodeStore;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Logout\SessionRegistry;
use PhpSso\OAuthServer\Pkce\Pkce;
use PhpSso\OAuthServer\Token\TokenGenerator;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The authorization endpoint (RFC 6749 section 3.1, OpenID Connect Core section 3.1.2): checks the request,
 * and when a person is signed in and allowed, redirects back to the client with a one-time code.
 *
 * Who is signed in comes from request attributes your own login middleware sets: {@see self::USER_ID}
 * and, if you track login sessions, {@see self::SESSION_ID}.
 *
 * Errors about the client or redirect URI are never redirected (that would make this an open redirector);
 * they go to the {@see ErrorResponder}. Every other error is redirected to the client, per the RFC.
 */
final readonly class AuthorizationHandler implements RequestHandlerInterface
{
    public const USER_ID = 'oauth.user_id';
    public const SESSION_ID = 'oauth.session_id';
    /**
     * Unix time the signed-in person last actually authenticated (typed their password), not when the session
     * began. Needed for `max_age` and for the ID token's `auth_time`; without it, `max_age` always forces a login.
     */
    public const AUTH_TIME = 'oauth.auth_time';
    /**
     * How the signed-in person authenticated, as a list of method names (RFC 8176: `pwd`, `otp`, `mfa`, ...). It becomes the
     * ID token's `amr` and stays with the code and every refresh token of the chain. Only strings without spaces are kept;
     * anything else is ignored, so a mistake in the application cannot put junk into a token.
     */
    public const AMR = 'oauth.amr';
    /**
     * Set to true on the request passed to {@see AuthorizationUi::loginRequired()} when the person must
     * authenticate again even though a session exists (`prompt=login`, or `max_age` exceeded).
     */
    public const FORCE_LOGIN = 'oauth.force_login';
    /**
     * Set on the request passed to {@see AuthorizationUi::loginRequired()}: the parameters of this authorization
     * request without `prompt` and `max_age`, as an array. After login, send the browser back to the
     * authorization endpoint with exactly these, so the request is not forced to log in again forever.
     */
    public const RESUME_PARAMS = 'oauth.resume_params';

    public function __construct(
        private ServerConfig $config,
        private ClientRepository $clients,
        private ScopeValidator $scopes,
        private AccessPolicy $policy,
        private AuthorizationUi $ui,
        private AuthorizationCodeStore $codes,
        private TokenGenerator $generator,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
        private SessionRegistry $sessions,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $params = $request->getMethod() === 'POST' ? Params::fromBody($request) : Params::fromQuery($request);
            $client = $this->clients->find($params->required('client_id'));
            if ($client === null) {
                throw OAuthException::invalidRequest('Unknown client_id.');
            }
            $redirectUri = $params->required('redirect_uri');
            if (!in_array($redirectUri, $client->redirectUris(), true)) {
                throw OAuthException::invalidRequest('The redirect_uri is not registered for this client.');
            }
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        // From here on the redirect URI is trusted, so errors go back to the client.
        $state = null;
        try {
            $state = $params->string('state');
            $authorization = $this->validate($params, $client, $redirectUri, $state);
            $userId = $request->getAttribute(self::USER_ID);
            $resume = $request->withAttribute(self::RESUME_PARAMS, array_diff_key($params->all(), ['prompt' => true, 'max_age' => true]));
            $authTime = $request->getAttribute(self::AUTH_TIME);
            $authTime = is_int($authTime) ? $authTime : null;
            $amr = self::methods($request->getAttribute(self::AMR));

            if (!is_string($userId) || $userId === '') {
                if ($authorization->promptNone) {
                    throw OAuthException::loginRequired('Nobody is signed in and prompt=none was requested.');
                }

                return $this->ui->loginRequired($resume);
            }
            if ($authorization->promptLogin || $this->tooOld($authorization->maxAge, $authTime)) {
                if ($authorization->promptNone) {
                    throw OAuthException::loginRequired('The person must authenticate again and prompt=none was requested.');
                }

                return $this->ui->loginRequired($resume->withAttribute(self::FORCE_LOGIN, true));
            }
            if (!$this->policy->mayUse($client, $userId)) {
                return $this->ui->accessDenied($request, $client);
            }

            $sessionId = $request->getAttribute(self::SESSION_ID);

            return $this->issueCode($authorization, $userId, is_string($sessionId) && $sessionId !== '' ? $sessionId : null, $authTime, $amr);
        } catch (OAuthException $e) {
            return $this->redirectError($redirectUri, $state, $e);
        }
    }

    /** @throws OAuthException */
    private function validate(Params $params, Client $client, string $redirectUri, ?string $state): AuthorizationRequest
    {
        if ($params->required('response_type') !== 'code') {
            throw OAuthException::unsupportedResponseType('Only response_type=code is supported.');
        }
        if (!$client->allowsGrant(GrantType::AuthorizationCode)) {
            throw OAuthException::unauthorizedClient('This client may not use the authorization code flow.');
        }
        // Request objects are not supported. Ignoring the parameter would answer a request that is not the one the
        // client made (its state, nonce and scope may live inside the object), so say so instead.
        if ($params->string('request') !== null) {
            throw OAuthException::requestNotSupported('The request parameter (request objects) is not supported.');
        }
        if ($params->string('request_uri') !== null) {
            throw OAuthException::requestUriNotSupported('The request_uri parameter is not supported.');
        }

        $challenge = $params->string('code_challenge');
        if ($challenge === null && $params->string('code_challenge_method') === null && !$this->pkceRequired($client)) {
            $challenge = Pkce::NONE; // a confidential client that leaves PKCE out, which this server was told to allow
        } else {
            if ($challenge === null || !Pkce::isValidChallenge($challenge)) {
                throw OAuthException::invalidRequest('A valid code_challenge is required (PKCE).');
            }
            if ($params->string('code_challenge_method') !== Pkce::METHOD) {
                throw OAuthException::invalidRequest('The code_challenge_method must be S256.');
            }
        }

        $prompts = array_values(array_unique(array_filter(explode(' ', $params->string('prompt') ?? ''), static fn (string $p): bool => $p !== '')));
        if (array_diff($prompts, ['none', 'login']) !== []) {
            throw OAuthException::invalidRequest('Only prompt=none and prompt=login are supported.');
        }
        if (in_array('none', $prompts, true) && count($prompts) > 1) {
            throw OAuthException::invalidRequest('prompt=none cannot be combined with other values.');
        }

        $maxAge = $params->string('max_age');
        if ($maxAge !== null && preg_match('/^\d{1,9}$/', $maxAge) !== 1) {
            throw OAuthException::invalidRequest('The max_age must be a number of seconds.');
        }

        return new AuthorizationRequest(
            $client,
            $redirectUri,
            $this->scopes->validate($client, $params->string('scope')),
            $challenge,
            $state,
            $params->string('nonce'),
            in_array('none', $prompts, true),
            in_array('login', $prompts, true),
            $maxAge === null ? null : (int) $maxAge,
        );
    }

    /** Public clients always need PKCE; confidential ones unless the server was told they may leave it out. */
    private function pkceRequired(Client $client): bool
    {
        return !$client->isConfidential() || $this->config->requirePkceForConfidentialClients;
    }

    /** @param list<string>|null $amr */
    private function issueCode(AuthorizationRequest $request, string $userId, ?string $sessionId, ?int $authTime, ?array $amr): ResponseInterface
    {
        if ($sessionId !== null) {
            $this->sessions->register($sessionId, $request->client->id()); // so logout can tell this client
        }

        $code = $this->generator->generate();
        $this->codes->save(new AuthorizationCodeRecord(
            TokenHash::of($code),
            $request->client->id(),
            $userId,
            $request->redirectUri,
            $request->scopes,
            $request->codeChallenge,
            $request->nonce,
            $sessionId,
            $this->generator->generate(),
            $this->clock->now()->getTimestamp() + $this->config->authorizationCodeTtl,
            null,
            $authTime,
            $amr,
        ));

        return $this->responses->redirect($request->redirectUri, array_filter([
            'code' => $code,
            'state' => $request->state,
            'iss' => $this->config->issuer, // RFC 9207: lets the client detect a mix-up between servers
        ], static fn (?string $v): bool => $v !== null));
    }

    /**
     * The authentication methods the application reported: a list of non-empty strings without spaces, each once.
     *
     * @return list<string>|null null when there are none worth keeping
     */
    private static function methods(mixed $value): ?array
    {
        if (!is_array($value)) {
            return null;
        }
        $methods = [];
        foreach ($value as $method) {
            if (is_string($method) && $method !== '' && strlen($method) <= 64 && preg_match('/\s/', $method) !== 1) {
                $methods[] = $method;
            }
        }
        $methods = array_values(array_unique($methods));

        return $methods === [] ? null : $methods;
    }

    /** Whether the person's last authentication is older than `max_age` allows. Unknown age counts as too old. */
    private function tooOld(?int $maxAge, ?int $authTime): bool
    {
        return $maxAge !== null && ($authTime === null || $this->clock->now()->getTimestamp() - $authTime > $maxAge);
    }

    private function redirectError(string $redirectUri, ?string $state, OAuthException $error): ResponseInterface
    {
        return $this->responses->redirect($redirectUri, array_filter([
            'error' => $error->error,
            'error_description' => $error->errorDescription,
            'state' => $state,
            'iss' => $this->config->issuer,
        ], static fn (?string $v): bool => $v !== null));
    }
}
