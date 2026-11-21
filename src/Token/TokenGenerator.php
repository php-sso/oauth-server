<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/** Source of the opaque secrets handed to clients (authorization codes, refresh tokens). */
interface TokenGenerator
{
    /** A new unguessable value, safe to put in a URL or header. */
    public function generate(): string;
}
