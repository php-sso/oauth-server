<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemorySessionRegistry;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemorySessionRegistry;

#[CoversMethod(InMemorySessionRegistry::class, 'register')]
final class RegisterTest extends TestCase
{
    public function testItRemembersWhichClientsTookPartInASession(): void
    {
        // Arrange
        $registry = new InMemorySessionRegistry();

        // Act
        $registry->register('s1', 'web');
        $registry->register('s1', 'spa');
        $registry->register('s2', 'tv');

        // Assert
        self::assertSame(['web', 'spa'], $registry->clientsOf('s1'));
        self::assertSame(['tv'], $registry->clientsOf('s2'));
    }

    public function testRegisteringTwiceIsHarmless(): void
    {
        // Arrange
        $registry = new InMemorySessionRegistry();
        $registry->register('s1', 'web');

        // Act
        $registry->register('s1', 'web');

        // Assert
        self::assertSame(['web'], $registry->clientsOf('s1'));
    }
}
