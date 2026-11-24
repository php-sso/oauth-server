<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Registration\ClientRegistration;
use PhpSso\OAuthServer\Registration\ClientRegistrations;

/** Keeps registered clients in memory: for tests and examples, not for production. */
final class InMemoryClientRegistrations implements ClientRegistrations
{
    /** @var array<string, ClientRegistration> */
    private array $registrations = [];

    public function find(string $clientId): ?ClientRegistration
    {
        return $this->registrations[$clientId] ?? null;
    }

    public function save(ClientRegistration $registration): void
    {
        $this->registrations[$registration->clientId] = $registration;
    }

    public function delete(string $clientId): void
    {
        unset($this->registrations[$clientId]);
    }
}
