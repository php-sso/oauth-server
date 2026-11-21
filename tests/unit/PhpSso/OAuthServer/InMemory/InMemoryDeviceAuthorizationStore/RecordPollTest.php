<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'recordPoll')]
final class RecordPollTest extends TestCase
{
    public function testItRemembersThePollAndInterval(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record());

        // Act
        $store->recordPoll('d1', 950, 10);

        // Assert
        $found = $store->findByDeviceCodeHash('d1');
        self::assertSame(950, $found?->lastPolledAt);
        self::assertSame(10, $found->interval);
    }

    public function testItIgnoresAnUnknownRequest(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();

        // Act
        $store->recordPoll('nope', 950, 10);

        // Assert
        self::assertNull($store->findByDeviceCodeHash('nope'));
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
