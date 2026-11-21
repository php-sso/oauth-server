<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/**
 * Claims the library sets itself. Whatever a {@see \PhpSso\OAuthServer\Authorization\UserClaimsProvider}
 * returns under these names is dropped, so an application bug cannot forge the issuer, subject or audience
 * of a token or of the userinfo response.
 */
final class ReservedClaims
{
    private const NAMES = ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'nonce', 'sid', 'fid', 'at_hash', 'c_hash', 'auth_time', 'acr', 'amr', 'azp', 'client_id', 'scope', 'gty'];

    /**
     * @param array<string, mixed> $claims
     *
     * @return array<string, mixed>
     */
    public static function strip(array $claims): array
    {
        return array_diff_key($claims, array_flip(self::NAMES));
    }
}
