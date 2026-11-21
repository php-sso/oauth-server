<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use PhpSso\OAuthServer\Logout\SessionTerminator;

final class TestSessionTerminator implements SessionTerminator
{
    /** @var list<string> */
    public array $terminated = [];

    public function terminate(string $sessionId): void
    {
        $this->terminated[] = $sessionId;
    }
}
