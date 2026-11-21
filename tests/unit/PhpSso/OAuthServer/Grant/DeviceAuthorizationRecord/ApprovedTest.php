<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Grant\DeviceAuthorizationRecord;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceStatus;

#[CoversMethod(DeviceAuthorizationRecord::class, 'approved')]
final class ApprovedTest extends TestCase
{
    public function testItRecordsWhoApprovedAndKeepsTheRest(): void
    {
        // Arrange
        $request = new DeviceAuthorizationRecord('d', 'u', 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);

        // Act
        $approved = $request->approved('user-1', 'session-1');

        // Assert
        self::assertSame(DeviceStatus::Approved, $approved->status);
        self::assertSame('user-1', $approved->userId);
        self::assertSame('session-1', $approved->sessionId);
        self::assertSame('tv', $approved->clientId);
        self::assertSame(DeviceStatus::Pending, $request->status); // the original is untouched
    }
}
