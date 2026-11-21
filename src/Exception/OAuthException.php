<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Exception;

use RuntimeException;

/**
 * An OAuth 2.0 protocol error: an RFC 6749 error code, a human-readable description for the developer
 * of the client, and the HTTP status the endpoint answers with. Create one through the named constructors.
 */
final class OAuthException extends RuntimeException
{
    private function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
        public readonly int $httpStatus,
    ) {
        parent::__construct($error . ': ' . $errorDescription);
    }

    public static function invalidRequest(string $description): self
    {
        return new self('invalid_request', $description, 400);
    }

    public static function invalidClient(string $description): self
    {
        return new self('invalid_client', $description, 401);
    }

    public static function invalidGrant(string $description): self
    {
        return new self('invalid_grant', $description, 400);
    }

    public static function unauthorizedClient(string $description): self
    {
        return new self('unauthorized_client', $description, 400);
    }

    public static function unsupportedGrantType(string $description): self
    {
        return new self('unsupported_grant_type', $description, 400);
    }

    public static function unsupportedResponseType(string $description): self
    {
        return new self('unsupported_response_type', $description, 400);
    }

    public static function invalidScope(string $description): self
    {
        return new self('invalid_scope', $description, 400);
    }

    public static function accessDenied(string $description): self
    {
        return new self('access_denied', $description, 403);
    }

    public static function serverError(string $description): self
    {
        return new self('server_error', $description, 500);
    }

    /** RFC 7009: the endpoint cannot revoke this kind of token. */
    public static function unsupportedTokenType(string $description): self
    {
        return new self('unsupported_token_type', $description, 400);
    }

    /** RFC 8628: the person has not finished approving the device yet; keep polling. */
    public static function authorizationPending(): self
    {
        return new self('authorization_pending', 'The person has not approved this device yet.', 400);
    }

    /** RFC 8628: the device polls too fast; it must wait longer between requests. */
    public static function slowDown(): self
    {
        return new self('slow_down', 'Polling too fast. Wait longer between requests.', 400);
    }

    /** RFC 8628: the device code expired before the person approved it. */
    public static function expiredToken(): self
    {
        return new self('expired_token', 'The device code has expired.', 400);
    }

    /** OpenID Connect Core 3.1.2.6: the request uses the `request` parameter (a request object), which is not supported. */
    public static function requestNotSupported(string $description): self
    {
        return new self('request_not_supported', $description, 400);
    }

    /** OpenID Connect Core 3.1.2.6: the request uses the `request_uri` parameter, which is not supported. */
    public static function requestUriNotSupported(string $description): self
    {
        return new self('request_uri_not_supported', $description, 400);
    }

    /** OpenID Connect: `prompt=none` was requested but nobody is signed in. */
    public static function loginRequired(string $description): self
    {
        return new self('login_required', $description, 400);
    }

    /** RFC 6750: the access token is missing, malformed, expired or revoked. */
    public static function invalidToken(string $description): self
    {
        return new self('invalid_token', $description, 401);
    }

    /** RFC 6750: the access token is valid but does not carry the scope the resource needs. */
    public static function insufficientScope(string $description): self
    {
        return new self('insufficient_scope', $description, 403);
    }

    /** @return array{error: string, error_description: string} the JSON body of an error response */
    public function toArray(): array
    {
        return ['error' => $this->error, 'error_description' => $this->errorDescription];
    }
}
