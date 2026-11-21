<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Logout;

/** Remembers which clients took part in which login session, so they can be told when it ends. */
interface SessionRegistry
{
    /** Called every time a code is issued to a client during a session. Registering twice is harmless. */
    public function register(string $sessionId, string $clientId): void;

    /** @return list<string> every client registered for the session */
    public function clientsOf(string $sessionId): array;
}
