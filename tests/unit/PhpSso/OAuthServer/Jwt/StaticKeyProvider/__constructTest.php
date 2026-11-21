<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\StaticKeyProvider;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(StaticKeyProvider::class, '__construct')]
final class __constructTest extends TestCase
{
    public function testItRejectsTwoKeysWithTheSameKid(): void
    {
        // Arrange
        $signingKey = TestKeys::signingKey('same');
        $retired = TestKeys::signingKey('same', 'b')->verificationKey();
        $this->expectException(InvalidArgumentException::class);

        // Act
        new StaticKeyProvider($signingKey, [$retired]);
    }
}
