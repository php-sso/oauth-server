<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Resource\ResourcePolicy;

final class TestResourcePolicy implements ResourcePolicy
{
    /** @param array<string, list<string>> $allowed client id => the resources it may get tokens for */
    public function __construct(public array $allowed = [])
    {
    }

    public function allows(Client $client, string $resource): bool
    {
        return in_array($resource, $this->allowed[$client->id()] ?? [], true);
    }
}
