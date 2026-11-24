<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

/** What the server remembers about a refresh token. Only the hash of the token itself is stored. */
final readonly class RefreshTokenRecord
{
    /**
     * @param list<string> $scopes
     * @param string       $familyId  Shared by the whole rotation chain that started at one authorization code.
     * @param int          $expiresAt Unix time.
     * @param int|null     $usedAt    Unix time it was exchanged for a new token, null while current.
     * @param int|null     $authTime  Unix time the person actually signed in; carried to every ID token of the chain.
     * @param list<string>|null $amr  How the person signed in; carried to every ID token of the chain, like `authTime`.
     * @param list<string> $resources What the grant was for (RFC 8707), carried through every rotation; empty when none were named. Stores must keep them.
     */
    public function __construct(
        public string $tokenHash,
        public string $familyId,
        public string $clientId,
        public string $userId,
        public array $scopes,
        public ?string $sessionId,
        public int $expiresAt,
        public ?int $usedAt,
        public ?int $authTime,
        public ?array $amr = null,
        public array $resources = [],
    ) {
    }
}
