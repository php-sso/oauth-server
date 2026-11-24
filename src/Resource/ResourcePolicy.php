<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Resource;

use PhpSso\OAuthServer\Client\Client;

/**
 * Which resources (APIs, named by an absolute URI) a client may get access tokens for (RFC 8707). Optional: without one
 * the `resource` parameter is ignored and access tokens keep their usual audience.
 */
interface ResourcePolicy
{
    /** Whether tokens for this client may be issued for the resource. Asked again on every refresh, so taking a resource away works at once. */
    public function allows(Client $client, string $resource): bool;
}
