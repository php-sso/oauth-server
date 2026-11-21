<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Middleware;

use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\FamilyRevocations;
use PhpSso\OAuthServer\Grant\RevokedAccessTokens;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Token\AccessTokenVerifier;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Protects a route with an OAuth access token (RFC 6750, RFC 9068). Rejects the request with 401 unless
 * it carries a valid, current, unrevoked access token for this API, and passes the facts about the token
 * on as request attributes. It works for any API, not just this server's own userinfo endpoint.
 *
 * ID tokens are refused: only tokens typed `at+jwt` count.
 */
final readonly class BearerTokenMiddleware implements MiddlewareInterface
{
    /** The person the token acts for; null for client credentials tokens, which act for the client alone. */
    public const USER_ID = 'oauth.token.user_id';
    public const CLIENT_ID = 'oauth.token.client_id';
    /** The scopes of the token, as a list of strings. */
    public const SCOPES = 'oauth.token.scopes';
    public const GRANT_TYPE = 'oauth.token.grant_type';
    public const SESSION_ID = 'oauth.token.session_id';
    public const TOKEN_ID = 'oauth.token.id';

    private AccessTokenVerifier $verifier;

    /**
     * @param string       $audience       The `aud` this API accepts.
     * @param list<string> $requiredScopes Scopes the token must carry; a token missing one gets 403.
     */
    public function __construct(
        JwtDecoder $decoder,
        ClaimsValidator $validator,
        private ErrorResponder $errors,
        string $audience,
        FamilyRevocations $revocations,
        RevokedAccessTokens $revokedTokens,
        private array $requiredScopes = [],
    ) {
        $this->verifier = new AccessTokenVerifier($decoder, $validator, $audience, $revocations, $revokedTokens);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            return $handler->handle($this->authenticate($request));
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }
    }

    /** @throws OAuthException */
    private function authenticate(ServerRequestInterface $request): ServerRequestInterface
    {
        if (preg_match('/^Bearer\s+([A-Za-z0-9._~+\/-]+=*)$/', $request->getHeaderLine('Authorization'), $match) !== 1) {
            throw OAuthException::invalidToken('Send the access token as "Authorization: Bearer <token>".');
        }

        $token = $this->verifier->verify($match[1]);

        foreach ($this->requiredScopes as $required) {
            if (!in_array($required, $token->scopes, true)) {
                throw OAuthException::insufficientScope("The access token lacks the {$required} scope.");
            }
        }

        return $request
            ->withAttribute(self::USER_ID, $token->userId())
            ->withAttribute(self::CLIENT_ID, $token->clientId)
            ->withAttribute(self::SCOPES, $token->scopes)
            ->withAttribute(self::GRANT_TYPE, $token->grant->value)
            ->withAttribute(self::SESSION_ID, $token->sessionId)
            ->withAttribute(self::TOKEN_ID, $token->tokenId);
    }
}
