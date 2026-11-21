<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Client;

interface ClientRepository
{
    public function find(string $clientId): ?Client;

    /** Whether the secret is the client's. Compare in constant time against a stored hash. */
    public function verifySecret(Client $client, string $secret): bool;
}
