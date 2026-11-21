<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Grant\DeviceAuthorizationRecord;

use PhpSso\OAuthServer\Grant\DeviceStatus;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;

#[CoversMethod(DeviceAuthorizationRecord::class, 'consumed')]
final class ConsumedTest extends TestCase
{
    public function testItRemembersWhenTheTokensWereHandedOut(): void
    {
        // Arrange
        $request = new DeviceAuthorizationRecord('d', 'u', 'tv', ['openid'], 'family', 1000, 5, DeviceStatus::Pending, null, null, null, null);

        // Act
        $consumed = $request->consumed(950);

        // Assert
        self::assertSame(950, $consumed->consumedAt);
    }
}
