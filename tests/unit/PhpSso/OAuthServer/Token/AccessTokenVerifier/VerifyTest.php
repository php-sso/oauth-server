<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\AccessTokenVerifier;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Tests\Support\JwtForge;
use PhpSso\OAuthServer\Tests\Support\TestKeys;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Token\AccessTokenVerifier;

#[CoversMethod(AccessTokenVerifier::class, 'verify')]
final class VerifyTest extends TestCase
{
    private TestServer $t;
    private AccessTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->t = new TestServer();
        $this->verifier = new AccessTokenVerifier(
            new JwtDecoder($this->t->keys),
            new ClaimsValidator($this->t->clock, TestServer::ISSUER),
            TestServer::ISSUER,
            $this->t->refreshTokens,
            $this->t->revokedTokens,
        );
    }

    public function testItReturnsTheFactsOfAGoodToken(): void
    {
        // Arrange
        $jwt = $this->t->str($this->t->signIn(), 'access_token');

        // Act
        $token = $this->verifier->verify($jwt);

        // Assert
        self::assertSame('user-1', $token->subject);
        self::assertSame('web', $token->clientId);
        self::assertSame(['openid', 'profile'], $token->scopes);
        self::assertSame(GrantType::AuthorizationCode, $token->grant);
        self::assertSame('session-1', $token->sessionId);
        self::assertSame($this->t->clock->timestamp() + 3600, $token->expiresAt);
        self::assertSame($this->t->clock->timestamp(), $token->issuedAt);
        self::assertNotNull($token->familyId);
    }

    public function testItRefusesATokenThatWasRevokedOnItsOwn(): void
    {
        // Arrange
        $jwt = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->revokedTokens->revoke($this->verifier->verify($jwt)->tokenId, 2_000_000_000);
        $this->expectException(OAuthException::class);

        // Act
        $this->verifier->verify($jwt);
    }

    public function testItRefusesATokenWhoseFamilyWasRevoked(): void
    {
        // Arrange
        $jwt = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->refreshTokens->revokeSession('session-1', $this->t->clock->timestamp());
        $this->expectException(OAuthException::class);

        // Act
        $this->verifier->verify($jwt);
    }

    public function testItRefusesAnIdToken(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');
        $this->expectException(OAuthException::class);

        // Act
        $this->verifier->verify($idToken);
    }

    public function testItRefusesAnExpiredToken(): void
    {
        // Arrange
        $jwt = $this->t->str($this->t->signIn(), 'access_token');
        $this->t->clock->advance(3631);
        $this->expectException(OAuthException::class);

        // Act
        $this->verifier->verify($jwt);
    }

    public function testItRefusesATokenForAnotherAudience(): void
    {
        // Arrange
        $jwt = $this->t->str($this->t->signIn(), 'access_token');
        $other = new AccessTokenVerifier(new JwtDecoder($this->t->keys), new ClaimsValidator($this->t->clock, TestServer::ISSUER), 'https://other-api.example', $this->t->refreshTokens, $this->t->revokedTokens);
        $this->expectException(OAuthException::class);

        // Act
        $other->verify($jwt);
    }

    public function testItRefusesATokenWithAnUnknownGrantType(): void
    {
        // Arrange
        $forged = JwtForge::rs256(['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => 'key-1'], [
            'iss' => TestServer::ISSUER, 'sub' => 'u', 'aud' => TestServer::ISSUER, 'client_id' => 'web', 'scope' => 'openid',
            'jti' => 'x', 'gty' => 'password', 'exp' => $this->t->clock->timestamp() + 60,
        ], TestKeys::privatePem('a'));
        $this->expectException(OAuthException::class);

        // Act
        $this->verifier->verify($forged);
    }
}
