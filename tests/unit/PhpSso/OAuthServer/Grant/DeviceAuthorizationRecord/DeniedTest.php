<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Grant\DeviceAuthorizationRecord;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceStatus;

#[CoversMethod(DeviceAuthorizationRecord::class, 'denied')]
final class DeniedTest extends TestCase
{
    public function testItIsMarkedDenied(): void
    {
        // Arrange
        $request = new DeviceAuthorizationRecord('d', 'u', 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);

        // Act
        $denied = $request->denied();

        // Assert
        self::assertSame(DeviceStatus::Denied, $denied->status);
    }
}
