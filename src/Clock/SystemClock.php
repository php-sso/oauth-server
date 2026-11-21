<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Clock;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/** The real time. Tests use a frozen clock instead. */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
