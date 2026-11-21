<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

use PhpSso\OAuthServer\Authorization\UserClaimsProvider;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Encoding\Base64Url;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Grant\RefreshTokenRecord;
use PhpSso\OAuthServer\Grant\RefreshTokenStore;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use Psr\Clock\ClockInterface;

/** Creates the access token, refresh token and ID token for a successful grant. */
final readonly class TokenIssuer
{
    public function __construct(
        private ServerConfig $config,
        private JwtEncoder $encoder,
        private TokenGenerator $generator,
        private RefreshTokenStore $refreshTokens,
        private UserClaimsProvider $claims,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Tokens for the client itself (client credentials grant): an access token whose subject is the client,
     * with no refresh token and no ID token, because no person is involved.
     *
     * @param list<string> $scopes
     */
    public function issueForClient(Client $client, array $scopes): IssuedTokens
    {
        $now = $this->clock->now()->getTimestamp();

        $accessToken = $this->encoder->encode([
            'iss' => $this->config->issuer,
            'sub' => $client->id(),
            'aud' => $this->audienceFor($client),
            'client_id' => $client->id(),
            'scope' => implode(' ', $scopes),
            'iat' => $now,
            'exp' => $now + $this->config->accessTokenTtl,
            'jti' => $this->generator->generate(),
            'gty' => GrantType::ClientCredentials->value,
        ], 'at+jwt');

        return new IssuedTokens($accessToken, $this->config->accessTokenTtl, $scopes, null, null);
    }

    /**
     * @param list<string> $scopes
     * @param string       $familyId  The rotation chain the refresh token belongs to; also stamped on the access token.
     * @param int|null     $authTime  When the person signed in; becomes the ID token's `auth_time`.
     * @param list<string>|null $amr  How they signed in; becomes the ID token's `amr` (left out when null or empty).
     *
     * @throws OAuthException when the person no longer exists
     */
    public function issue(Client $client, string $userId, array $scopes, ?string $sessionId, string $familyId, ?string $nonce, GrantType $grant, ?int $authTime, ?array $amr = null): IssuedTokens
    {
        $userClaims = $this->claims->claimsFor($userId, $scopes);
        if ($userClaims === null) {
            throw OAuthException::invalidGrant('The person is no longer allowed to sign in.');
        }
        $clientClaims = ClientClaims::of($this->claims, $client->id(), $userId, $scopes);
        $userClaims = ReservedClaims::strip($userClaims) + $clientClaims;

        $now = $this->clock->now()->getTimestamp();
        $session = $sessionId === null ? [] : ['sid' => $sessionId];

        $accessToken = $this->encoder->encode([
            'iss' => $this->config->issuer,
            'sub' => $userId,
            'aud' => $this->audienceFor($client),
            'client_id' => $client->id(),
            'scope' => implode(' ', $scopes),
            'iat' => $now,
            'exp' => $now + $this->config->accessTokenTtl,
            'jti' => $this->generator->generate(),
            'fid' => $familyId,
            'gty' => $grant->value,
        ] + $session + $clientClaims, 'at+jwt');

        $refreshToken = null;
        if ($client->allowsGrant(GrantType::RefreshToken)) {
            $refreshToken = $this->generator->generate();
            $this->refreshTokens->save(new RefreshTokenRecord(
                TokenHash::of($refreshToken), $familyId, $client->id(), $userId, $scopes, $sessionId, $now + $this->config->refreshTokenTtl, null, $authTime, $amr,
            ));
        }

        $idToken = null;
        if (in_array('openid', $scopes, true)) {
            $idToken = $this->encoder->encode($userClaims + [
                'iss' => $this->config->issuer,
                'sub' => $userId,
                'aud' => $client->id(),
                'iat' => $now,
                'exp' => $now + $this->config->idTokenTtl,
                'at_hash' => Base64Url::encode(substr(hash('sha256', $accessToken, true), 0, 16)),
            ] + ($nonce === null ? [] : ['nonce' => $nonce]) + ($authTime === null ? [] : ['auth_time' => $authTime]) + ($amr === null || $amr === [] ? [] : ['amr' => $amr]) + $session);
        }

        return new IssuedTokens($accessToken, $this->config->accessTokenTtl, $scopes, $refreshToken, $idToken);
    }

    /**
     * Who an access token is for: this server (its own userinfo, introspection and revocation endpoints accept
     * it) and the client it was issued to. An API that serves one application checks for that application's
     * client id, so a token issued to one application does not work at another's API.
     *
     * @return string|list<string> a single string when both are the same
     */
    private function audienceFor(Client $client): string|array
    {
        $audiences = array_values(array_unique([$this->config->audience(), $client->id()]));

        return count($audiences) === 1 ? $audiences[0] : $audiences;
    }
}
