<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

interface DeviceAuthorizationStore
{
    public function save(DeviceAuthorizationRecord $request): void;

    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord;

    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord;

    /** Pending to approved, for the person who entered the user code. Atomic; false unless it was pending. */
    public function approve(string $deviceCodeHash, string $userId, ?string $sessionId): bool;

    /** Pending to denied. Atomic; false unless it was pending. */
    public function deny(string $deviceCodeHash): bool;

    /** Remembers when the device polled and the interval now required of it. */
    public function recordPoll(string $deviceCodeHash, int $at, int $interval): void;

    /** Atomic: exactly one caller gets true, so an approved request pays out tokens once. */
    public function markConsumed(string $deviceCodeHash, int $at): bool;
}
