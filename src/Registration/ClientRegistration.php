<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\SupportsLogout;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Token\TokenHash;

/**
 * A client that registered itself (or was registered for someone) through the registration endpoint.
 * It is a {@see Client}, so your {@see \PhpSso\OAuthServer\Client\ClientRepository} can return it as it is.
 * Secrets are stored as hashes only; the plain values are shown once, in the registration response.
 */
final readonly class ClientRegistration implements Client, SupportsLogout
{
    /**
     * @param string|null $secretHash            {@see TokenHash::of()} of the client secret; null for a public client.
     * @param string      $registrationTokenHash {@see TokenHash::of()} of the registration access token (RFC 7592).
     * @param string|null $registeredBy          The client id of the access token that registered it, for ownership and clean-up.
     */
    public function __construct(
        public string $clientId,
        public ClientMetadata $metadata,
        public ?string $secretHash,
        public string $registrationTokenHash,
        public int $issuedAt,
        public ?string $registeredBy = null,
    ) {
    }

    public function withMetadata(ClientMetadata $metadata, ?string $secretHash): self
    {
        return new self($this->clientId, $metadata, $secretHash, $this->registrationTokenHash, $this->issuedAt, $this->registeredBy);
    }

    /** Whether the secret is this client's. Constant time. */
    public function verifySecret(string $secret): bool
    {
        return $this->secretHash !== null && hash_equals($this->secretHash, TokenHash::of($secret));
    }

    public function verifyRegistrationToken(string $token): bool
    {
        return hash_equals($this->registrationTokenHash, TokenHash::of($token));
    }

    public function id(): string
    {
        return $this->clientId;
    }

    public function redirectUris(): array
    {
        return $this->metadata->redirectUris;
    }

    public function isConfidential(): bool
    {
        return $this->metadata->isConfidential();
    }

    public function allowsGrant(GrantType $grant): bool
    {
        return in_array($grant, $this->metadata->grantTypes, true);
    }

    public function allowsScope(string $scope): bool
    {
        return in_array($scope, $this->metadata->scopes, true);
    }

    public function backchannelLogoutUri(): ?string
    {
        return $this->metadata->backchannelLogoutUri;
    }

    public function postLogoutRedirectUris(): array
    {
        return $this->metadata->postLogoutRedirectUris;
    }
}
