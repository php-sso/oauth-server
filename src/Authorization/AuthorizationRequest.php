<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Authorization;

use PhpSso\OAuthServer\Client\Client;

/** A validated request to the authorization endpoint. */
final readonly class AuthorizationRequest
{
    /** @param list<string> $scopes */
    public function __construct(
        public Client $client,
        public string $redirectUri,
        public array $scopes,
        public string $codeChallenge,
        public ?string $state,
        public ?string $nonce,
        public bool $promptNone,
        public bool $promptLogin,
        public ?int $maxAge,
    ) {
    }
}
