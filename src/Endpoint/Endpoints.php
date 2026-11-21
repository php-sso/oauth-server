<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

/** Where the endpoints are mounted. Paths are resolved against the issuer; absolute URLs are used as they are. */
final readonly class Endpoints
{
    public function __construct(
        public string $authorization = '/authorize',
        public string $token = '/token',
        public string $userinfo = '/userinfo',
        public string $jwks = '/jwks',
        public string $endSession = '/end-session',
        public string $deviceAuthorization = '/device_authorization',
        public string $deviceVerification = '/device',
        public string $revocation = '/revoke',
        public string $introspection = '/introspect',
    ) {
    }

    public static function url(string $issuer, string $pathOrUrl): string
    {
        return str_starts_with($pathOrUrl, 'https://') || str_starts_with($pathOrUrl, 'http://') ? $pathOrUrl : $issuer . '/' . ltrim($pathOrUrl, '/');
    }
}
