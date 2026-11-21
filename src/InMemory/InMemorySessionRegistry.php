<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Logout\SessionRegistry;

/** Keeps the session-to-client links in memory: for tests and examples, not for production. */
final class InMemorySessionRegistry implements SessionRegistry
{
    /** @var array<string, array<string, true>> */
    private array $clients = [];

    public function register(string $sessionId, string $clientId): void
    {
        $this->clients[$sessionId][$clientId] = true;
    }

    public function clientsOf(string $sessionId): array
    {
        return array_map('strval', array_keys($this->clients[$sessionId] ?? []));
    }
}
