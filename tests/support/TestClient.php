<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\SupportsLogout;
use PhpSso\OAuthServer\Grant\GrantType;

final readonly class TestClient implements Client, SupportsLogout
{
    /**
     * @param list<string>    $redirectUris
     * @param list<GrantType> $grants
     * @param list<string>    $scopes
     * @param list<string>    $postLogoutRedirectUris
     */
    public function __construct(
        public string $id,
        public array $redirectUris,
        public bool $confidential,
        public array $grants,
        public array $scopes,
        public ?string $secret = null,
        public ?string $backchannelLogoutUri = null,
        public array $postLogoutRedirectUris = [],
    ) {
    }

    public function id(): string
    {
        return $this->id;
    }

    public function redirectUris(): array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }

    public function allowsGrant(GrantType $grant): bool
    {
        return in_array($grant, $this->grants, true);
    }

    public function allowsScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function backchannelLogoutUri(): ?string
    {
        return $this->backchannelLogoutUri;
    }

    public function postLogoutRedirectUris(): array
    {
        return $this->postLogoutRedirectUris;
    }
}
