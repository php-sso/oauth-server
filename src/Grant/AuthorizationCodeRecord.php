<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/**
 * What the server remembers about an issued authorization code: who it was for, what was asked, and the
 * PKCE challenge it must be redeemed with. Only the hash of the code itself is stored.
 */
final readonly class AuthorizationCodeRecord
{
    /**
     * @param list<string> $scopes
     * @param string       $familyId  Ties together every token issued from this code, so they can all be revoked at once.
     * @param int          $expiresAt Unix time.
     * @param int|null     $usedAt    Unix time of the first redemption, null while unused.
     * @param int|null     $authTime  Unix time the person actually signed in, for the ID token's `auth_time`.
     * @param list<string>|null $amr  How the person signed in (RFC 8176 values such as `pwd`, `otp`, `mfa`), for the ID token's `amr`.
     */
    public function __construct(
        public string $codeHash,
        public string $clientId,
        public string $userId,
        public string $redirectUri,
        public array $scopes,
        public string $codeChallenge,
        public ?string $nonce,
        public ?string $sessionId,
        public string $familyId,
        public int $expiresAt,
        public ?int $usedAt,
        public ?int $authTime,
        public ?array $amr = null,
    ) {
    }
}
