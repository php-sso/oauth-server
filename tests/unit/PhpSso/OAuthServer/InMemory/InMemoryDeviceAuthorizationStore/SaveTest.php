<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'save')]
final class SaveTest extends TestCase
{
    public function testItReplacesARequestSavedUnderTheSameDeviceCode(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record('d1', 'u1'));

        // Act
        $store->save($this->record('d1', 'u9'));

        // Assert
        self::assertSame('u9', $store->findByDeviceCodeHash('d1')?->userCodeHash);
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
