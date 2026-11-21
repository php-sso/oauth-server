<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

use PhpSso\OAuthServer\Grant\GrantType;

/** The facts in an access token that passed every check. */
final readonly class VerifiedAccessToken
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $issuer,
        public string $subject,
        public string $audience,
        public string $clientId,
        public array $scopes,
        public GrantType $grant,
        public string $tokenId,
        public int $expiresAt,
        public ?int $issuedAt,
        public ?string $familyId,
        public ?string $sessionId,
    ) {
    }

    /** The person the token acts for; null for client credentials tokens, which act for the client alone. */
    public function userId(): ?string
    {
        return $this->grant === GrantType::ClientCredentials ? null : $this->subject;
    }
}
