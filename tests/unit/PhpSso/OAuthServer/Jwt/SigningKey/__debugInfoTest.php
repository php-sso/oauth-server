<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\SigningKey;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\SigningKey;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(SigningKey::class, '__debugInfo')]
final class __debugInfoTest extends TestCase
{
    public function testADumpOfTheKeyShowsItsKidAndNeverTheKeyMaterial(): void
    {
        // Arrange
        $key = new SigningKey('key-1', TestKeys::privatePem());

        // Act
        $dump = print_r($key, true);

        // Assert
        self::assertStringContainsString('key-1', $dump);
        self::assertStringNotContainsString('PRIVATE KEY', $dump);
    }
}
