<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\FamilyRevocations;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Grant\RevokedAccessTokens;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\InvalidJwt;
use PhpSso\OAuthServer\Jwt\JwtDecoder;

/**
 * Decides whether a string is a good access token (RFC 9068): our signature, type `at+jwt` (so ID and logout
 * tokens do not count), the right issuer and audience, not expired, and not revoked, either on its own or
 * with its whole family. Used by the bearer middleware and the introspection endpoint.
 */
final readonly class AccessTokenVerifier
{
    public function __construct(
        private JwtDecoder $decoder,
        private ClaimsValidator $validator,
        private string $audience,
        private FamilyRevocations $familyRevocations,
        private RevokedAccessTokens $revokedTokens,
    ) {
    }

    /** @throws OAuthException invalid_token, without saying which check failed */
    public function verify(string $jwt): VerifiedAccessToken
    {
        $invalid = OAuthException::invalidToken('The access token is not valid.');

        try {
            $token = $this->decoder->decode($jwt);
            if (($token['header']['typ'] ?? null) !== 'at+jwt') {
                throw new InvalidJwt('This is not an access token.');
            }
            $this->validator->validate($token['claims'], $this->audience);
        } catch (InvalidJwt) {
            throw $invalid;
        }

        $claims = $token['claims'];
        $issuer = $claims['iss'] ?? null;
        $subject = $claims['sub'] ?? null;
        $clientId = $claims['client_id'] ?? null;
        $scope = $claims['scope'] ?? null;
        $tokenId = $claims['jti'] ?? null;
        $expiresAt = $claims['exp'] ?? null;
        $grant = GrantType::tryFrom(is_string($claims['gty'] ?? null) ? $claims['gty'] : '');
        if (!is_string($issuer) || !is_string($subject) || !is_string($clientId) || !is_string($scope) || !is_string($tokenId) || !is_int($expiresAt) || $grant === null) {
            throw $invalid;
        }

        $family = $claims['fid'] ?? null;
        $family = is_string($family) ? $family : null;
        if (($family !== null && $this->familyRevocations->isFamilyRevoked($family)) || $this->revokedTokens->isRevoked($tokenId)) {
            throw OAuthException::invalidToken('The access token has been revoked.');
        }

        $session = $claims['sid'] ?? null;
        $issuedAt = $claims['iat'] ?? null;

        return new VerifiedAccessToken(
            $issuer,
            $subject,
            $this->audience,
            $clientId,
            array_values(array_filter(explode(' ', $scope), static fn (string $s): bool => $s !== '')),
            $grant,
            $tokenId,
            $expiresAt,
            is_int($issuedAt) ? $issuedAt : null,
            $family,
            is_string($session) ? $session : null,
        );
    }
}
