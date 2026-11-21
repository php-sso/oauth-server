<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Token\AccessTokenVerifier;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The token introspection endpoint (RFC 7662). An API that does not want to validate JWTs itself, or that
 * needs to know about revocation right now, asks whether a token is active.
 *
 * The caller must be a confidential client. Every failure looks the same, `{"active": false}`: the caller
 * learns nothing about why a token is not good. Refresh tokens can only be introspected by the client they
 * were issued to; access tokens by any authenticated client, since APIs are the point of this endpoint.
 */
final readonly class IntrospectionHandler implements RequestHandlerInterface
{
    public function __construct(
        private ClientAuthenticator $authenticator,
        private RefreshTokenStore $refreshTokens,
        private AccessTokenVerifier $accessTokens,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw OAuthException::invalidRequest('The introspection endpoint only accepts POST.');
            }
            $body = Params::fromBody($request);
            $caller = $this->authenticator->authenticate($request, $body);
            if (!$caller->isConfidential()) {
                throw OAuthException::invalidClient('Only confidential clients may introspect tokens.');
            }
            $token = $body->required('token');
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->responses->noStore($this->responses->json($this->introspect($token, $caller->id())));
    }

    /** @return array<string, mixed> */
    private function introspect(string $token, string $callerId): array
    {
        $now = $this->clock->now()->getTimestamp();

        $refresh = $this->refreshTokens->find(TokenHash::of($token));
        if ($refresh !== null) {
            if ($refresh->clientId !== $callerId || $refresh->usedAt !== null || $refresh->expiresAt <= $now || $this->refreshTokens->isFamilyRevoked($refresh->familyId)) {
                return ['active' => false];
            }

            return [
                'active' => true,
                'scope' => implode(' ', $refresh->scopes),
                'client_id' => $refresh->clientId,
                'sub' => $refresh->userId,
                'exp' => $refresh->expiresAt,
            ];
        }

        try {
            $access = $this->accessTokens->verify($token);
        } catch (OAuthException) {
            return ['active' => false];
        }

        return array_filter([
            'active' => true,
            'scope' => implode(' ', $access->scopes),
            'client_id' => $access->clientId,
            'token_type' => 'Bearer',
            'exp' => $access->expiresAt,
            'iat' => $access->issuedAt,
            'sub' => $access->subject,
            'aud' => $access->audience,
            'iss' => $access->issuer,
            'jti' => $access->tokenId,
            'sid' => $access->sessionId,
        ], static fn (mixed $v): bool => $v !== null);
    }
}
