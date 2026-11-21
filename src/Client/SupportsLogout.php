<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Client;

/**
 * Implement this on your {@see Client} to take part in logout. Clients that do not implement it are never
 * sent a back-channel logout request and may not use `post_logout_redirect_uri`.
 */
interface SupportsLogout
{
    /**
     * Where to POST the logout token when someone's session ends (OpenID Connect Back-Channel Logout 1.0),
     * or null for a client that does not want to be told.
     */
    public function backchannelLogoutUri(): ?string;

    /**
     * Exact URIs the client may send people to after it asked for them to be signed out.
     *
     * @return list<string>
     */
    public function postLogoutRedirectUris(): array;
}
