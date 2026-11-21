<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Pkce\Pkce;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Pkce\Pkce;

#[CoversMethod(Pkce::class, 'verify')]
final class VerifyTest extends TestCase
{
    public function testItAcceptsTheVerifierThatMatchesTheChallenge(): void
    {
        // Arrange
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

        // Act
        $matches = Pkce::verify($challenge, $verifier);

        // Assert
        self::assertTrue($matches);
    }

    public function testItRejectsAnotherVerifier(): void
    {
        // Arrange
        $challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

        // Act
        $matches = Pkce::verify($challenge, str_repeat('a', 43));

        // Assert
        self::assertFalse($matches);
    }

    public function testItRejectsAVerifierThatIsTooShortEvenIfItsHashMatches(): void
    {
        // Arrange
        $verifier = 'short';
        $challenge = Pkce::challengeFor($verifier);

        // Act
        $matches = Pkce::verify($challenge, $verifier);

        // Assert
        self::assertFalse($matches);
    }
}
