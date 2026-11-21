<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Grant\DeviceAuthorizationRecord;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;

#[CoversMethod(DeviceAuthorizationRecord::class, 'polled')]
final class PolledTest extends TestCase
{
    public function testItRemembersTheLastPollAndTheNewInterval(): void
    {
        // Arrange
        $request = new DeviceAuthorizationRecord('d', 'u', 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);

        // Act
        $polled = $request->polled(900, 10);

        // Assert
        self::assertSame(900, $polled->lastPolledAt);
        self::assertSame(10, $polled->interval);
    }
}
