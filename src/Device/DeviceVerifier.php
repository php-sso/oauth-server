<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Device;

use PhpSso\OAuthServer\Authorization\AccessPolicy;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Client\ClientRepository;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationStore;
use PhpSso\OAuthServer\Grant\DeviceStatus;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Clock\ClockInterface;

/**
 * The person's side of the device flow. Your verification page asks for the user code, shows who is
 * asking ({@see self::lookup()}), and after the person is signed in calls {@see self::approve()} or
 * {@see self::deny()}.
 *
 * User codes are short, so limit how many wrong codes one person or address can try; this class does
 * not know who is asking.
 */
final readonly class DeviceVerifier
{
    public function __construct(
        private DeviceAuthorizationStore $devices,
        private ClientRepository $clients,
        private AccessPolicy $policy,
        private ClockInterface $clock,
    ) {
    }

    /** The pending request for the code a person typed, or null for an unknown, expired or finished one. */
    public function lookup(string $typedUserCode): ?PendingDevice
    {
        $request = $this->pendingRequest($typedUserCode);
        $client = $request === null ? null : $this->clients->find($request->clientId);

        return $request === null || $client === null
            ? null
            : new PendingDevice($client, $request->scopes, RandomUserCodeGenerator::format(RandomUserCodeGenerator::normalize($typedUserCode)));
    }

    /**
     * @param string|null $sessionId the login session of the person, so ending it revokes the device's tokens
     *
     * @throws OAuthException when the code is not valid or the person may not use the client
     */
    public function approve(string $typedUserCode, string $userId, ?string $sessionId): void
    {
        [$request, $client] = $this->require($typedUserCode);
        if (!$this->policy->mayUse($client, $userId)) {
            throw OAuthException::accessDenied('This person may not use this client.');
        }
        if (!$this->devices->approve($request->deviceCodeHash, $userId, $sessionId)) {
            throw OAuthException::invalidGrant('The code was already used.');
        }
    }

    /** @throws OAuthException when the code is not valid */
    public function deny(string $typedUserCode): void
    {
        [$request] = $this->require($typedUserCode);
        $this->devices->deny($request->deviceCodeHash);
    }

    private function pendingRequest(string $typedUserCode): ?DeviceAuthorizationRecord
    {
        $request = $this->devices->findByUserCodeHash(TokenHash::of(RandomUserCodeGenerator::normalize($typedUserCode)));

        if ($request === null || $request->status !== DeviceStatus::Pending || $request->expiresAt <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        return $request;
    }

    /**
     * @return array{DeviceAuthorizationRecord, Client}
     *
     * @throws OAuthException
     */
    private function require(string $typedUserCode): array
    {
        $request = $this->pendingRequest($typedUserCode);
        $client = $request === null ? null : $this->clients->find($request->clientId);
        if ($request === null || $client === null) {
            throw OAuthException::invalidGrant('That code is not valid or has expired.');
        }

        return [$request, $client];
    }
}
