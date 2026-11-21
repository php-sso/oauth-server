<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Authorization\AccessPolicy;
use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\AuthorizationCodeStore;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationStore;
use PhpSso\OAuthServer\Grant\DeviceStatus;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Pkce\Pkce;
use PhpSso\OAuthServer\Token\IssuedTokens;
use PhpSso\OAuthServer\Token\TokenHash;
use PhpSso\OAuthServer\Token\TokenIssuer;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The token endpoint (RFC 6749 section 3.2). Supports the authorization code grant (with PKCE), the refresh
 * token grant (with rotation), the client credentials grant and the device code grant (RFC 8628).
 *
 * A replayed authorization code or refresh token revokes everything issued from it (RFC 9700).
 */
final readonly class TokenHandler implements RequestHandlerInterface
{
    /** Added to the polling interval each time a device polls too fast (RFC 8628 section 3.5). */
    private const SLOW_DOWN_STEP = 5;

    public function __construct(
        private ClientAuthenticator $authenticator,
        private ScopeValidator $scopes,
        private AuthorizationCodeStore $codes,
        private RefreshTokenStore $refreshTokens,
        private DeviceAuthorizationStore $devices,
        private AccessPolicy $policy,
        private TokenIssuer $issuer,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw OAuthException::invalidRequest('The token endpoint only accepts POST.');
            }
            $body = Params::fromBody($request);
            $client = $this->authenticator->authenticate($request, $body);

            $grant = GrantType::tryFrom($body->required('grant_type'))
                ?? throw OAuthException::unsupportedGrantType('This grant type is not supported.');
            if (!$client->allowsGrant($grant)) {
                throw OAuthException::unauthorizedClient('This client may not use this grant type.');
            }

            $tokens = match ($grant) {
                GrantType::AuthorizationCode => $this->authorizationCode($client, $body),
                GrantType::RefreshToken => $this->refreshToken($client, $body),
                GrantType::ClientCredentials => $this->clientCredentials($client, $body),
                GrantType::DeviceCode => $this->deviceCode($client, $body),
            };
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->responses->noStore($this->responses->json($tokens->toResponseBody()));
    }

    /** @throws OAuthException */
    private function authorizationCode(Client $client, Params $body): IssuedTokens
    {
        $now = $this->clock->now()->getTimestamp();
        $hash = TokenHash::of($body->required('code'));
        $invalid = OAuthException::invalidGrant('The authorization code is not valid.');

        $code = $this->codes->find($hash);
        if ($code === null || $code->clientId !== $client->id()) {
            throw $invalid;
        }
        if ($code->usedAt !== null) {
            $this->refreshTokens->revokeFamily($code->familyId, $now); // replay: what came out of it is suspect
            throw $invalid;
        }
        if ($code->expiresAt <= $now) {
            throw OAuthException::invalidGrant('The authorization code has expired.');
        }
        // From here the code is spent, whether or not the rest checks out: a guessed verifier gets one try.
        if (!$this->codes->markUsed($hash, $now)) {
            $this->refreshTokens->revokeFamily($code->familyId, $now); // lost a race with another redemption
            throw $invalid;
        }

        if ($body->required('redirect_uri') !== $code->redirectUri) {
            throw OAuthException::invalidGrant('The redirect_uri does not match the authorization request.');
        }
        if ($code->codeChallenge === Pkce::NONE) {
            // Asked for without PKCE (a confidential client, on a server that allows it). A verifier now would mean the
            // request that started this was not the client's own, so it is refused rather than ignored.
            if ($body->string('code_verifier') !== null) {
                throw OAuthException::invalidGrant('The authorization request had no code_challenge, so there is no code_verifier to check.');
            }
        } elseif (!Pkce::verify($code->codeChallenge, $body->required('code_verifier'))) {
            throw OAuthException::invalidGrant('The code_verifier does not match the code_challenge.');
        }
        $this->assertMayUse($client, $code->userId);

        return $this->issuer->issue($client, $code->userId, $code->scopes, $code->sessionId, $code->familyId, $code->nonce, GrantType::AuthorizationCode, $code->authTime, $code->amr);
    }

    /** @throws OAuthException */
    private function refreshToken(Client $client, Params $body): IssuedTokens
    {
        $now = $this->clock->now()->getTimestamp();
        $hash = TokenHash::of($body->required('refresh_token'));
        $invalid = OAuthException::invalidGrant('The refresh token is not valid.');

        $token = $this->refreshTokens->find($hash);
        if ($token === null || $token->clientId !== $client->id() || $this->refreshTokens->isFamilyRevoked($token->familyId)) {
            throw $invalid;
        }
        if ($token->usedAt !== null) {
            $this->refreshTokens->revokeFamily($token->familyId, $now); // an old token came back: someone has a copy
            throw $invalid;
        }
        if ($token->expiresAt <= $now) {
            throw OAuthException::invalidGrant('The refresh token has expired.');
        }

        // Checked before the token is spent: a request that asks for too much is refused, and the client keeps its token.
        $scopes = $token->scopes;
        $requested = $body->string('scope');
        if ($requested !== null) {
            $scopes = array_values(array_unique(array_filter(explode(' ', $requested), static fn (string $s): bool => $s !== '')));
            if (array_diff($scopes, $token->scopes) !== []) {
                throw OAuthException::invalidScope('A refresh cannot widen the scope.');
            }
        }
        // What the client may ask for can change after the token was issued: a refresh only carries what is still allowed.
        $scopes = $this->scopes->stillAllowed($client, $scopes);
        if ($scopes === []) {
            throw OAuthException::invalidGrant('The scopes this refresh token was issued for are no longer available to the client.');
        }
        if (!$this->refreshTokens->markUsed($hash, $now)) {
            $this->refreshTokens->revokeFamily($token->familyId, $now);
            throw $invalid;
        }
        $this->assertMayUse($client, $token->userId);

        return $this->issuer->issue($client, $token->userId, $scopes, $token->sessionId, $token->familyId, null, GrantType::RefreshToken, $token->authTime, $token->amr);
    }

    /** @throws OAuthException */
    private function clientCredentials(Client $client, Params $body): IssuedTokens
    {
        if (!$client->isConfidential()) {
            throw OAuthException::unauthorizedClient('Only confidential clients may use client credentials.');
        }

        return $this->issuer->issueForClient($client, $this->scopes->validate($client, $body->string('scope')));
    }

    /** @throws OAuthException */
    private function deviceCode(Client $client, Params $body): IssuedTokens
    {
        $now = $this->clock->now()->getTimestamp();
        $hash = TokenHash::of($body->required('device_code'));

        $request = $this->devices->findByDeviceCodeHash($hash);
        if ($request === null || $request->clientId !== $client->id() || $request->consumedAt !== null) {
            throw OAuthException::invalidGrant('The device code is not valid.');
        }
        if ($request->expiresAt <= $now) {
            throw OAuthException::expiredToken();
        }

        $this->throttle($request, $now);

        if ($request->status === DeviceStatus::Denied) {
            $this->devices->markConsumed($hash, $now);
            throw OAuthException::accessDenied('The person declined the request.');
        }
        if ($request->status === DeviceStatus::Pending || $request->userId === null) {
            throw OAuthException::authorizationPending();
        }
        if (!$this->devices->markConsumed($hash, $now)) {
            throw OAuthException::invalidGrant('The device code is not valid.');
        }
        $this->assertMayUse($client, $request->userId);

        return $this->issuer->issue($client, $request->userId, $request->scopes, $request->sessionId, $request->familyId, null, GrantType::DeviceCode, null);
    }

    /** A device that polls faster than the interval is told to slow down, and the interval grows. */
    private function throttle(DeviceAuthorizationRecord $request, int $now): void
    {
        if ($request->lastPolledAt !== null && $now - $request->lastPolledAt < $request->interval) {
            $this->devices->recordPoll($request->deviceCodeHash, $now, $request->interval + self::SLOW_DOWN_STEP);
            throw OAuthException::slowDown();
        }
        $this->devices->recordPoll($request->deviceCodeHash, $now, $request->interval);
    }

    /** @throws OAuthException */
    private function assertMayUse(Client $client, string $userId): void
    {
        if (!$this->policy->mayUse($client, $userId)) {
            throw OAuthException::invalidGrant('This person may no longer use this client.');
        }
    }
}
