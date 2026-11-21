<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Authorization\AccessPolicy;
use PhpSso\OAuthServer\Client\Client;

final class TestAccessPolicy implements AccessPolicy
{
    /** @var array<string, true> keyed "clientId|userId" */
    public array $denied = [];

    public function mayUse(Client $client, string $userId): bool
    {
        return !isset($this->denied[$client->id() . '|' . $userId]);
    }
}
