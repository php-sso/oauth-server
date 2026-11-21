<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

/** Where the server's signing keys come from. The application decides how keys are stored and rotated. */
interface KeyProvider extends VerificationKeys
{
    /** The key new tokens are signed with. */
    public function signingKey(): SigningKey;

    /**
     * Every public key tokens may still be verified with: the current one first, then retired keys whose
     * tokens have not expired yet. This is also what the JWKS endpoint publishes.
     *
     * @return list<VerificationKey>
     */
    public function verificationKeys(): array;
}
