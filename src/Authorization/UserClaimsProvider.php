<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

/** Where the information about people comes from. The application implements it. */
interface UserClaimsProvider
{
    /**
     * The claims to release for the scopes granted, for example `name` and `email` for the `profile` and
     * `email` scopes. `sub` is added by the library and must not be returned here.
     *
     * Returns null when the person no longer exists or may no longer sign in; the library then refuses
     * to issue or refresh tokens for them.
     *
     * @param list<string> $scopes
     *
     * @return array<string, mixed>|null
     */
    public function claimsFor(string $userId, array $scopes): ?array;
}
