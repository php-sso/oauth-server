<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Registration\RegistrarPolicy;

final class TestRegistrarPolicy implements RegistrarPolicy
{
    /** @param array<string, list<string>|null> $registrars client id => scopes its apps may get (null: the default) */
    public function __construct(public array $registrars = [])
    {
    }

    public function mayRegister(string $registrarClientId): bool
    {
        return array_key_exists($registrarClientId, $this->registrars);
    }

    public function allowedScopes(string $registrarClientId): ?array
    {
        return $this->registrars[$registrarClientId] ?? null;
    }

    public function anyRegistrar(): bool
    {
        return $this->registrars !== [];
    }
}
