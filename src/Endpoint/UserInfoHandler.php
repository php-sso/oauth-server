<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Authorization\UserClaimsProvider;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Middleware\BearerTokenMiddleware;
use PhpSso\OAuthServer\Token\ClientClaims;
use PhpSso\OAuthServer\Token\ReservedClaims;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The OpenID Connect UserInfo endpoint. Put {@see BearerTokenMiddleware} in front of it: this handler
 * reads who the token is for from the attributes the middleware sets.
 */
final readonly class UserInfoHandler implements RequestHandlerInterface
{
    public function __construct(
        private UserClaimsProvider $claims,
        private Responses $responses,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $userId = $request->getAttribute(BearerTokenMiddleware::USER_ID);
            $scopes = $request->getAttribute(BearerTokenMiddleware::SCOPES);
            if (!is_string($userId) || !is_array($scopes)) {
                throw OAuthException::invalidToken('This token is not for a person.');
            }
            $scopes = array_values(array_filter($scopes, 'is_string'));
            if (!in_array('openid', $scopes, true)) {
                throw OAuthException::insufficientScope('The access token lacks the openid scope.');
            }

            $claims = $this->claims->claimsFor($userId, $scopes)
                ?? throw OAuthException::invalidToken('The person no longer exists.');
            $clientId = $request->getAttribute(BearerTokenMiddleware::CLIENT_ID);
            $clientClaims = is_string($clientId) ? ClientClaims::of($this->claims, $clientId, $userId, $scopes) : [];
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        return $this->responses->noStore($this->responses->json(['sub' => $userId] + ReservedClaims::strip($claims) + $clientClaims));
    }
}
