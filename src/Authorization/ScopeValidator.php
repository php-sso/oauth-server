<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;

/** Turns the `scope` parameter into a list the server offers and the client is allowed to ask for. */
final readonly class ScopeValidator
{
    public function __construct(private ServerConfig $config)
    {
    }

    /**
     * @return non-empty-list<string>
     *
     * @throws OAuthException
     */
    public function validate(Client $client, ?string $requested): array
    {
        $scopes = array_values(array_unique(array_filter(explode(' ', $requested ?? ''), static fn (string $s): bool => $s !== '')));
        if ($scopes === []) {
            throw OAuthException::invalidScope('Request at least one scope.');
        }

        foreach ($scopes as $scope) {
            if (!$this->config->supportsScope($scope) || !$client->allowsScope($scope)) {
                throw OAuthException::invalidScope("The scope {$scope} is not available to this client.");
            }
        }

        return $scopes;
    }

    /**
     * The scopes of an earlier grant that are still available: one the server stopped offering, or that the client may no
     * longer ask for, is dropped, so taking a scope away also stops tokens that were already on their way.
     *
     * @param list<string> $scopes
     *
     * @return list<string>
     */
    public function stillAllowed(Client $client, array $scopes): array
    {
        return array_values(array_filter($scopes, fn (string $scope): bool => $this->config->supportsScope($scope) && $client->allowsScope($scope)));
    }
}
