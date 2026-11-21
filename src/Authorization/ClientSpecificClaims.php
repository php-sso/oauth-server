<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

/**
 * Implement this on your {@see UserClaimsProvider} when some claims depend on the client the person signs in
 * to, for example the roles they have in that application. Providers that do not implement it release the
 * same claims to every client, and the access token carries no claims about the person.
 *
 * The claims returned here go into the access token, the ID token and the userinfo response, so an API
 * that only sees the access token can use them. They are read again on every refresh, so a change is
 * picked up when the access token is renewed. Claims named like ones the library controls (`sub`, `aud`,
 * ...) are dropped, as for {@see UserClaimsProvider}.
 */
interface ClientSpecificClaims
{
    /**
     * @param list<string> $scopes The scopes granted to the client; release a claim only for the scope that unlocks it.
     *
     * @return array<string, mixed> empty when there is nothing to release
     */
    public function clientClaimsFor(string $clientId, string $userId, array $scopes): array;
}
