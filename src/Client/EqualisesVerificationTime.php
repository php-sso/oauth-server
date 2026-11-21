<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Client;

/**
 * Implement this on your {@see ClientRepository} when checking a secret is slow on purpose (a password hash).
 * Without it, a request for a client id that does not exist is answered faster than one with a wrong secret,
 * which tells an attacker which ids exist. The server calls it for unknown ids, so both take about as long.
 */
interface EqualisesVerificationTime
{
    /** Do the same work as {@see ClientRepository::verifySecret()} would, against a secret nobody has. The result is thrown away. */
    public function spendVerificationTime(string $secret): void;
}
