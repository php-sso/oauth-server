<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/**
 * A device authorization request (RFC 8628): the device polls with the device code while the person
 * approves the user code on another screen. Only hashes of the two codes are stored.
 */
final readonly class DeviceAuthorizationRecord
{
    /**
     * @param list<string> $scopes
     * @param int          $expiresAt    Unix time.
     * @param int          $interval     Seconds the device must wait between polls; grows when it polls too fast.
     * @param int|null     $lastPolledAt Unix time of the latest poll.
     * @param int|null     $consumedAt   Unix time the tokens were handed out; a request pays out once.
     */
    public function __construct(
        public string $deviceCodeHash,
        public string $userCodeHash,
        public string $clientId,
        public array $scopes,
        public string $familyId,
        public int $expiresAt,
        public int $interval,
        public DeviceStatus $status,
        public ?string $userId,
        public ?string $sessionId,
        public ?int $lastPolledAt,
        public ?int $consumedAt,
    ) {
    }

    public function approved(string $userId, ?string $sessionId): self
    {
        return $this->copy(status: DeviceStatus::Approved, userId: $userId, sessionId: $sessionId);
    }

    public function denied(): self
    {
        return $this->copy(status: DeviceStatus::Denied);
    }

    public function polled(int $at, int $interval): self
    {
        return $this->copy(lastPolledAt: $at, interval: $interval);
    }

    public function consumed(int $at): self
    {
        return $this->copy(consumedAt: $at);
    }

    private function copy(
        ?DeviceStatus $status = null,
        ?string $userId = null,
        ?string $sessionId = null,
        ?int $lastPolledAt = null,
        ?int $interval = null,
        ?int $consumedAt = null,
    ): self {
        return new self(
            $this->deviceCodeHash,
            $this->userCodeHash,
            $this->clientId,
            $this->scopes,
            $this->familyId,
            $this->expiresAt,
            $interval ?? $this->interval,
            $status ?? $this->status,
            $userId ?? $this->userId,
            $sessionId ?? $this->sessionId,
            $lastPolledAt ?? $this->lastPolledAt,
            $consumedAt ?? $this->consumedAt,
        );
    }
}
