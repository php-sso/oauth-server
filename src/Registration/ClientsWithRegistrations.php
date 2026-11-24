<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Client\EqualisesVerificationTime;

/**
 * Your own clients plus the registered ones, as one {@see ClientRepository}. Your clients win when an id exists in both,
 * so a registration can never shadow a client you configured.
 */
final readonly class ClientsWithRegistrations implements ClientRepository, EqualisesVerificationTime
{
    public function __construct(private ClientRepository $clients, private ClientRegistrations $registrations)
    {
    }

    public function find(string $clientId): ?Client
    {
        return $this->clients->find($clientId) ?? $this->registrations->find($clientId);
    }

    public function verifySecret(Client $client, string $secret): bool
    {
        if ($client instanceof ClientRegistration) {
            return $client->verifySecret($secret);
        }

        return $this->clients->verifySecret($client, $secret);
    }

    public function spendVerificationTime(string $secret): void
    {
        if ($this->clients instanceof EqualisesVerificationTime) {
            $this->clients->spendVerificationTime($secret);

            return;
        }
        hash_equals(hash('sha256', 'x'), hash('sha256', $secret));
    }
}
