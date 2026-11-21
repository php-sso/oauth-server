<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemoryDeviceAuthorizationStore;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\InMemory\InMemoryDeviceAuthorizationStore;

#[CoversMethod(InMemoryDeviceAuthorizationStore::class, 'approve')]
final class ApproveTest extends TestCase
{
    public function testItApprovesAPendingRequestOnce(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();
        $store->save($this->record());

        // Act
        $first = $store->approve('d1', 'user-1', 'session-1');
        $second = $store->approve('d1', 'user-2', null);

        // Assert
        self::assertTrue($first);
        self::assertFalse($second);
        self::assertSame('user-1', $store->findByDeviceCodeHash('d1')?->userId);
    }

    public function testItRefusesAnUnknownRequest(): void
    {
        // Arrange
        $store = new InMemoryDeviceAuthorizationStore();

        // Act
        $result = $store->approve('nope', 'user-1', null);

        // Assert
        self::assertFalse($result);
    }

    private function record(string $device = 'd1', string $user = 'u1'): DeviceAuthorizationRecord
    {
        return new DeviceAuthorizationRecord($device, $user, 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);
    }
}
