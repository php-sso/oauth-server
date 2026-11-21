<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Authorization\ClientSpecificClaims;
use PhpSso\OAuthServer\Authorization\UserClaimsProvider;

final class TestClaimsProvider implements UserClaimsProvider, ClientSpecificClaims
{
    /** @var array<string, true> */
    public array $removed = [];

    /** @var array<string, array<string, mixed>> Claims released to a client, by client id. */
    public array $clientClaims = [];

    /** @var list<array{client: string, user: string, scopes: list<string>}> What clientClaimsFor() was asked. */
    public array $clientClaimRequests = [];

    public function claimsFor(string $userId, array $scopes): ?array
    {
        if (isset($this->removed[$userId]) || !in_array($userId, ['user-1', 'user-2'], true)) {
            return null;
        }

        $claims = [];
        if (in_array('profile', $scopes, true)) {
            $claims['name'] = 'Alice Example';
        }
        if (in_array('email', $scopes, true)) {
            $claims['email'] = 'alice@example.com';
            // A provider that tries to override what the library controls must not succeed.
            $claims['sub'] = 'forged';
            $claims['iss'] = 'https://evil.example';
        }

        return $claims;
    }

    public function clientClaimsFor(string $clientId, string $userId, array $scopes): array
    {
        $this->clientClaimRequests[] = ['client' => $clientId, 'user' => $userId, 'scopes' => $scopes];

        return $this->clientClaims[$clientId] ?? [];
    }
}
