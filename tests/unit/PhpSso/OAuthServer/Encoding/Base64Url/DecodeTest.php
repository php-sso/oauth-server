<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Encoding\Base64Url;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;

#[CoversMethod(Base64Url::class, 'decode')]
final class DecodeTest extends TestCase
{
    public function testItDecodesWhatEncodeProduced(): void
    {
        // Arrange
        $bytes = random_bytes(37);

        // Act
        $decoded = Base64Url::decode(Base64Url::encode($bytes));

        // Assert
        self::assertSame($bytes, $decoded);
    }

    #[DataProvider('invalidInput')]
    public function testItRejectsInvalidInput(string $text): void
    {
        // Act
        $decoded = Base64Url::decode($text);

        // Assert
        self::assertNull($decoded);
    }

    /** @return array<string, array{string}> */
    public static function invalidInput(): array
    {
        return [
            'padding' => ['Zm9vYg=='],
            'plain base64 characters' => ['a+b/'],
            'whitespace' => ['Zm9v YmFy'],
            'impossible length' => ['Zm9vY'],
            'leftover bits set in the last character' => ['Zm9vYh'], // decodes to the same bytes as the canonical "Zm9vYg"
        ];
    }

    public function testItAcceptsTheCanonicalSpellingOfBytesThatEndInPartialBits(): void
    {
        // Act
        $decoded = Base64Url::decode('Zm9vYg');

        // Assert
        self::assertSame('foob', $decoded);
    }
}
