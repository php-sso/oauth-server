<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\TokenHash;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\TokenHash;

#[CoversMethod(TokenHash::class, 'of')]
final class OfTest extends TestCase
{
    public function testItIsTheSha256HexDigest(): void
    {
        // Act
        $hash = TokenHash::of('abc');

        // Assert
        self::assertSame('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', $hash);
    }
}
