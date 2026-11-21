<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use PhpSso\OAuthServer\Grant\RevokedAccessTokens;
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
 * The token revocation endpoint (RFC 7009). A client says it no longer needs a token.
 *
 * Revoking a refresh token revokes everything issued from the same sign-in, because the access tokens it
 * produced are no longer wanted either. Revoking an access token revokes just that token, which is remembered in
 * the {@see RevokedAccessTokens} store until it would have expired anyway.
 *
 * As the RFC asks, the answer is 200 for tokens that are unknown, already expired, or belong to another
 * client, so the endpoint reveals nothing about tokens.
 */
final readonly class RevocationHandler implements RequestHandlerInterface
{
    public function __construct(
        private ClientAuthenticator $authenticator,
        private RefreshTokenStore $refreshTokens,
        private AccessTokenVerifier $accessTokens,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
        private RevokedAccessTokens $revoked,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw OAuthException::invalidRequest('The revocation endpoint only accepts POST.');
            }
            $body = Params::fromBody($request);
            $client = $this->authenticator->authenticate($request, $body);
            $token = $body->required('token');
            $now = $this->clock->now()->getTimestamp();

            $refresh = $this->refreshTokens->find(TokenHash::of($token));
            if ($refresh !== null) {
                if ($refresh->clientId === $client->id()) {
                    $this->refreshTokens->revokeFamily($refresh->familyId, $now);
                }

                return $this->done();
            }

            try {
                $access = $this->accessTokens->verify($token);
            } catch (OAuthException) {
                return $this->done(); // not a token we can act on: unknown, expired, revoked already, or not ours
            }
            if ($access->clientId !== $client->id()) {
                return $this->done();
            }
            $this->revoked->revoke($access->tokenId, $access->expiresAt);
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->done();
    }

    private function done(): ResponseInterface
    {
        return $this->responses->noStore($this->responses->json([]));
    }
}
