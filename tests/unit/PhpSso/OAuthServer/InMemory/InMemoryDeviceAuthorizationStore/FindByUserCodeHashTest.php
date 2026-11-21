<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'findByUserCodeHash')]
final class FindByUserCodeHashTest extends TestCase
{
    public function testItFindsASavedRequestByItsUserCode(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record('d1', 'u1'));
        $store->save($this->record('d2', 'u2'));

        // Act
        $found = $store->findByUserCodeHash('u2');

        // Assert
        self::assertSame('d2', $found?->deviceCodeHash);
        self::assertNull($store->findByUserCodeHash('nope'));
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
