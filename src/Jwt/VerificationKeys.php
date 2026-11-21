<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

/** The public keys signatures may be checked against. All a program needs to verify tokens it did not sign. */
interface VerificationKeys
{
    /** @return list<VerificationKey> */
    public function verificationKeys(): array;
}
