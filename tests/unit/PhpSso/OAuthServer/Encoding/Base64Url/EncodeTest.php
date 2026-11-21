<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Encoding\Base64Url;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;

#[CoversMethod(Base64Url::class, 'encode')]
final class EncodeTest extends TestCase
{
    public function testItEncodesWithoutPaddingAndWithTheUrlSafeAlphabet(): void
    {
        // Arrange
        $bytes = "\xfb\xff\xfe"; // would be "+//+" in plain base64

        // Act
        $encoded = Base64Url::encode($bytes);

        // Assert
        self::assertSame('-__-', $encoded);
        self::assertSame('Zm9vYg', Base64Url::encode('foob')); // padding removed
    }
}
