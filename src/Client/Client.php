<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Client;

use PhpSso\OAuthServer\Grant\GrantType;

/** An application registered with the server. The application using this library implements it. */
interface Client
{
    public function id(): string;

    /**
     * Exact redirect URIs. A request is accepted only when its `redirect_uri` equals one of these.
     *
     * @return list<string>
     */
    public function redirectUris(): array;

    /** Confidential clients can keep a secret and authenticate at the token endpoint; public clients cannot. */
    public function isConfidential(): bool;

    public function allowsGrant(GrantType $grant): bool;

    /** Whether the client may ask for the scope. For machine-to-machine clients this is what limits their access. */
    public function allowsScope(string $scope): bool;
}
