<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Device;

use PhpSso\OAuthServer\Client\Client;

/** What the confirmation screen shows before a person approves a device. */
final readonly class PendingDevice
{
    /** @param list<string> $scopes */
    public function __construct(public Client $client, public array $scopes, public string $userCode)
    {
    }
}
