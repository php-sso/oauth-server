<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

use PhpSso\OAuthServer\Authorization\ClientSpecificClaims;
use PhpSso\OAuthServer\Authorization\UserClaimsProvider;

/** Asks a claims provider for the claims that depend on the client, if it has any. */
final class ClientClaims
{
    /**
     * @param list<string> $scopes
     *
     * @return array<string, mixed> without the claims the library controls; empty for a provider that is not client specific
     */
    public static function of(UserClaimsProvider $provider, string $clientId, string $userId, array $scopes): array
    {
        if (!$provider instanceof ClientSpecificClaims) {
            return [];
        }

        return ReservedClaims::strip($provider->clientClaimsFor($clientId, $userId, $scopes));
    }
}
