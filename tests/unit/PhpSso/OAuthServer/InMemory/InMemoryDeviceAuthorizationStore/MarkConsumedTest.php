<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'markConsumed')]
final class MarkConsumedTest extends TestCase
{
    public function testItPaysOutOnlyOnce(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record());

        // Act
        $first = $store->markConsumed('d1', 950);
        $second = $store->markConsumed('d1', 951);

        // Assert
        self::assertTrue($first);
        self::assertFalse($second);
    }

    public function testItRefusesAnUnknownRequest(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();

        // Act
        $result = $store->markConsumed('nope', 950);

        // Assert
        self::assertFalse($result);
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
