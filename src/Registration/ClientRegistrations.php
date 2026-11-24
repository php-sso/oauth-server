<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

/**
 * Where registered clients are kept. Implement it on your database. Make your
 * {@see \PhpSso\OAuthServer\Client\ClientRepository} find these clients too, or wrap it in {@see ClientsWithRegistrations}.
 */
interface ClientRegistrations
{
    public function find(string $clientId): ?ClientRegistration;

    /** Stores a new registration, or replaces the one with the same client id. */
    public function save(ClientRegistration $registration): void;

    /**
     * Removes the client. Refresh tokens and codes of a client that no longer exists cannot be used, because
     * the client lookup fails. Access tokens already issued live until they expire.
     */
    public function delete(string $clientId): void;
}
