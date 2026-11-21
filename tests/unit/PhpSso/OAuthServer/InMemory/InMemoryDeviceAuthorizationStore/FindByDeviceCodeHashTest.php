<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'findByDeviceCodeHash')]
final class FindByDeviceCodeHashTest extends TestCase
{
    public function testItFindsASavedRequest(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record());

        // Act
        $found = $store->findByDeviceCodeHash('d1');

        // Assert
        self::assertSame('u1', $found?->userCodeHash);
        self::assertNull($store->findByDeviceCodeHash('nope'));
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
