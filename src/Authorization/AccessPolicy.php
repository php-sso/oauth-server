<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

use PhpSso\OAuthServer\Client\Client;

/** Decides whether a person may use a client at all, for example by group membership. */
interface AccessPolicy
{
    /** Asked when a code is issued, when it is redeemed, and on every refresh. */
    public function mayUse(Client $client, string $userId): bool;
}
