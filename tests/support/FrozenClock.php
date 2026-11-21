<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/** A clock that only moves when a test says so. */
final class FrozenClock implements ClockInterface
{
    private int $time;

    public function __construct(int $time = 1_700_000_000)
    {
        $this->time = $time;
    }

    public function now(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp($this->time);
    }

    public function advance(int $seconds): void
    {
        $this->time += $seconds;
    }

    public function timestamp(): int
    {
        return $this->time;
    }
}
