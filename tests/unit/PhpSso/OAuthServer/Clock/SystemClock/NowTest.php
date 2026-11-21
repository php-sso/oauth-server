<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Clock\SystemClock;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Clock\SystemClock;

#[CoversMethod(SystemClock::class, 'now')]
final class NowTest extends TestCase
{
    public function testItReturnsTheCurrentTime(): void
    {
        // Arrange
        $clock = new SystemClock();
        $before = time();

        // Act
        $now = $clock->now()->getTimestamp();

        // Assert
        self::assertGreaterThanOrEqual($before, $now);
        self::assertLessThanOrEqual(time(), $now);
    }
}
