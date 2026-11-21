<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Pkce\Pkce;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Pkce\Pkce;

#[CoversMethod(Pkce::class, 'challengeFor')]
final class ChallengeForTest extends TestCase
{
    public function testItMatchesTheExampleInRfc7636AppendixB(): void
    {
        // Arrange
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        // Act
        $challenge = Pkce::challengeFor($verifier);

        // Assert
        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $challenge);
    }
}
