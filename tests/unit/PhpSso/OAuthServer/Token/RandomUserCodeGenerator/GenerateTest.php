<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\RandomUserCodeGenerator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;

#[CoversMethod(RandomUserCodeGenerator::class, 'generate')]
final class GenerateTest extends TestCase
{
    public function testItProducesEightCharactersFromTheConsonantAlphabet(): void
    {
        // Arrange
        $generator = new RandomUserCodeGenerator();

        // Act
        $code = $generator->generate();

        // Assert
        self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{8}$/', $code);
        self::assertNotSame($code, $generator->generate());
    }
}
