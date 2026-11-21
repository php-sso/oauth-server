<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientRepository;

final class TestClientRepository implements ClientRepository
{
    /** @var array<string, TestClient> */
    private array $clients = [];

    public function add(TestClient $client): void
    {
        $this->clients[$client->id] = $client;
    }

    public function find(string $clientId): ?Client
    {
        return $this->clients[$clientId] ?? null;
    }

    public function verifySecret(Client $client, string $secret): bool
    {
        return $client instanceof TestClient && $client->secret !== null && hash_equals($client->secret, $secret);
    }
}
