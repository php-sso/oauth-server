<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Pkce\Pkce;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Pkce\Pkce;

#[CoversMethod(Pkce::class, 'isValidVerifier')]
final class IsValidVerifierTest extends TestCase
{
    #[DataProvider('cases')]
    public function testItAcceptsOnlyFortyThreeToOneHundredTwentyEightUnreservedCharacters(string $verifier, bool $expected): void
    {
        // Act
        $valid = Pkce::isValidVerifier($verifier);

        // Assert
        self::assertSame($expected, $valid);
    }

    /** @return array<string, array{string, bool}> */
    public static function cases(): array
    {
        return [
            'shortest allowed' => [str_repeat('a', 43), true],
            'longest allowed' => [str_repeat('a', 128), true],
            'all unreserved characters' => [str_repeat('aZ09-._~', 6), true],
            'too short' => [str_repeat('a', 42), false],
            'too long' => [str_repeat('a', 129), false],
            'forbidden character' => [str_repeat('a', 42) . ' ', false],
        ];
    }
}
