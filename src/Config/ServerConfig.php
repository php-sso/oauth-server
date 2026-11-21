<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Config;

use InvalidArgumentException;

/** Settings of the authorization server. Lifetimes are in seconds. */
final readonly class ServerConfig
{
    /**
     * @param string       $issuer                The `iss` of every token and the base of the discovery URLs; no trailing slash.
     * @param list<string> $scopes                Scopes clients may request.
     * @param int          $authorizationCodeTtl  How long a code can be exchanged.
     * @param int          $accessTokenTtl        Lifetime of access tokens.
     * @param int          $idTokenTtl            Lifetime of ID tokens.
     * @param int          $refreshTokenTtl       Lifetime of refresh tokens (each rotation starts a new one).
     * @param int          $deviceCodeTtl         How long a person has to approve a device (RFC 8628).
     * @param int          $deviceInterval        Seconds a device must wait between polls.
     * @param string|null  $accessTokenAudience   The server's own audience: what the userinfo, introspection and revocation endpoints
     *                                            check; the issuer when null. Access tokens also name the client they were issued to
     *                                            in `aud`, so an API checks for its client id.
     * @param bool         $requirePkceForConfidentialClients PKCE is always required of public clients. With true (the default, and what
     *                                            OAuth 2.1 asks for) confidential clients need it too. With false they may leave it out
     *                                            of a request, which OpenID Connect allows and the OpenID conformance suite relies on;
     *                                            a request that does send a challenge is still checked, and so is its verifier.
     */
    public function __construct(
        public string $issuer,
        public array $scopes = ['openid'],
        public int $authorizationCodeTtl = 60,
        public int $accessTokenTtl = 3600,
        public int $idTokenTtl = 3600,
        public int $refreshTokenTtl = 2592000,
        public int $deviceCodeTtl = 600,
        public int $deviceInterval = 5,
        public ?string $accessTokenAudience = null,
        public bool $requirePkceForConfidentialClients = true,
    ) {
        if (!str_starts_with($issuer, 'https://') && !str_starts_with($issuer, 'http://')) {
            throw new InvalidArgumentException('The issuer must be an http(s) URL.');
        }
        if (str_ends_with($issuer, '/')) {
            throw new InvalidArgumentException('The issuer must not end with a slash.');
        }
        if ($scopes === [] || count(array_unique($scopes)) !== count($scopes)) {
            throw new InvalidArgumentException('Provide at least one scope, without duplicates.');
        }
        foreach ($scopes as $scope) {
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
                throw new InvalidArgumentException("Invalid scope name: {$scope}");
            }
        }
        foreach (['authorizationCodeTtl' => $authorizationCodeTtl, 'accessTokenTtl' => $accessTokenTtl, 'idTokenTtl' => $idTokenTtl, 'refreshTokenTtl' => $refreshTokenTtl, 'deviceCodeTtl' => $deviceCodeTtl, 'deviceInterval' => $deviceInterval] as $name => $ttl) {
            if ($ttl < 1) {
                throw new InvalidArgumentException("{$name} must be at least one second.");
            }
        }
    }

    /** This server's own audience, which every access token carries (next to the client id) and the server's own endpoints check. */
    public function audience(): string
    {
        return $this->accessTokenAudience ?? $this->issuer;
    }

    public function supportsScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
