<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\InMemory;

use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationStore;
use PhpSso\OAuthServer\Grant\DeviceStatus;

/** Keeps device authorization requests in memory: for tests and examples, not for production. */
final class InMemoryDeviceAuthorizationStore implements DeviceAuthorizationStore
{
    /** @var array<string, DeviceAuthorizationRecord> keyed by device code hash */
    private array $requests = [];

    public function save(DeviceAuthorizationRecord $request): void
    {
        $this->requests[$request->deviceCodeHash] = $request;
    }

    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord
    {
        return $this->requests[$deviceCodeHash] ?? null;
    }

    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord
    {
        foreach ($this->requests as $request) {
            if ($request->userCodeHash === $userCodeHash) {
                return $request;
            }
        }

        return null;
    }

    public function approve(string $deviceCodeHash, string $userId, ?string $sessionId): bool
    {
        $request = $this->requests[$deviceCodeHash] ?? null;
        if ($request === null || $request->status !== DeviceStatus::Pending) {
            return false;
        }
        $this->requests[$deviceCodeHash] = $request->approved($userId, $sessionId);

        return true;
    }

    public function deny(string $deviceCodeHash): bool
    {
        $request = $this->requests[$deviceCodeHash] ?? null;
        if ($request === null || $request->status !== DeviceStatus::Pending) {
            return false;
        }
        $this->requests[$deviceCodeHash] = $request->denied();

        return true;
    }

    public function recordPoll(string $deviceCodeHash, int $at, int $interval): void
    {
        $request = $this->requests[$deviceCodeHash] ?? null;
        if ($request !== null) {
            $this->requests[$deviceCodeHash] = $request->polled($at, $interval);
        }
    }

    public function markConsumed(string $deviceCodeHash, int $at): bool
    {
        $request = $this->requests[$deviceCodeHash] ?? null;
        if ($request === null || $request->consumedAt !== null) {
            return false;
        }
        $this->requests[$deviceCodeHash] = $request->consumed($at);

        return true;
    }
}
