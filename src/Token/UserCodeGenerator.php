<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/** Source of the short code a person types on their phone or computer to approve a device. */
interface UserCodeGenerator
{
    /** A new code in its normalized form: upper case, no separator. */
    public function generate(): string;
}
