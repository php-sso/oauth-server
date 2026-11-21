<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

/** The tokens handed out by one successful token request. */
final readonly class IssuedTokens
{
    /**
     * @param non-empty-string      $accessToken
     * @param int                   $expiresIn    Seconds until the access token expires.
     * @param list<string>          $scopes
     * @param non-empty-string|null $idToken      Present when the `openid` scope was granted.
     */
    public function __construct(
        public string $accessToken,
        public int $expiresIn,
        public array $scopes,
        public ?string $refreshToken,
        public ?string $idToken,
    ) {
    }

    /** @return array<string, string|int> the JSON body of the token response (RFC 6749 section 5.1) */
    public function toResponseBody(): array
    {
        $body = [
            'access_token' => $this->accessToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->expiresIn,
            'scope' => implode(' ', $this->scopes),
        ];
        if ($this->refreshToken !== null) {
            $body['refresh_token'] = $this->refreshToken;
        }
        if ($this->idToken !== null) {
            $body['id_token'] = $this->idToken;
        }

        return $body;
    }
}
