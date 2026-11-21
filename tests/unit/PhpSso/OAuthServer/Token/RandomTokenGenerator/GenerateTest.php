<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\RandomTokenGenerator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\RandomTokenGenerator;

#[CoversMethod(RandomTokenGenerator::class, 'generate')]
final class GenerateTest extends TestCase
{
    public function testItProducesUnguessableUrlSafeValues(): void
    {
        // Arrange
        $generator = new RandomTokenGenerator();

        // Act
        $first = $generator->generate();
        $second = $generator->generate();

        // Assert
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $first);
        self::assertNotSame($first, $second);
    }
}
