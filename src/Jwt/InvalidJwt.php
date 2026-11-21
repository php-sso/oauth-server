<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use RuntimeException;

/** A token that cannot be trusted: malformed, wrongly signed, expired, or meant for someone else. */
final class InvalidJwt extends RuntimeException
{
}
