<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

/** The application's side of ending a session. Only the application knows where its sessions live. */
interface SessionTerminator
{
    /** Marks the login session as ended, so its browser is signed out on the next request. */
    public function terminate(string $sessionId): void;
}
