<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Client\EqualisesVerificationTime;

/** A repository that notes every time the server asks it to spend verification time. */
final class TimingAwareClientRepository implements ClientRepository, EqualisesVerificationTime
{
    /** @var list<string> */
    public array $spentOn = [];

    public function __construct(private ClientRepository $inner)
    {
    }

    public function find(string $clientId): ?Client
    {
        return $this->inner->find($clientId);
    }

    public function verifySecret(Client $client, string $secret): bool
    {
        return $this->inner->verifySecret($client, $secret);
    }

    public function spendVerificationTime(string $secret): void
    {
        $this->spentOn[] = $secret;
    }
}
