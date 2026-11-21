<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Pkce\Pkce;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Pkce\Pkce;

#[CoversMethod(Pkce::class, 'isValidChallenge')]
final class IsValidChallengeTest extends TestCase
{
    #[DataProvider('cases')]
    public function testItAcceptsOnlyAFortyThreeCharacterBase64UrlValue(string $challenge, bool $expected): void
    {
        // Act
        $valid = Pkce::isValidChallenge($challenge);

        // Assert
        self::assertSame($expected, $valid);
    }

    /** @return array<string, array{string, bool}> */
    public static function cases(): array
    {
        return [
            'a real challenge' => ['E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', true],
            'too short' => [str_repeat('a', 42), false],
            'too long' => [str_repeat('a', 44), false],
            'padding character' => [str_repeat('a', 42) . '=', false],
            'plain base64 character' => [str_repeat('a', 42) . '+', false],
            'empty' => ['', false],
        ];
    }
}
