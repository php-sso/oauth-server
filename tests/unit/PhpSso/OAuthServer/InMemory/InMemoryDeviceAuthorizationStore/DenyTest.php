<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'deny')]
final class DenyTest extends TestCase
{
    public function testItDeniesAPendingRequestButNotAnApprovedOne(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record('d1'));
        $store->save($this->record('d2', 'u2'));
        $store->approve('d2', 'user-1', null);

        // Act
        $denied = $store->deny('d1');
        $tooLate = $store->deny('d2');

        // Assert
        self::assertTrue($denied);
        self::assertFalse($tooLate);
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
