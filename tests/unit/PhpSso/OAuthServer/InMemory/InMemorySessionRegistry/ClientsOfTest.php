<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\InMemory\InMemorySessionRegistry;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\InMemory\InMemorySessionRegistry;

#[CoversMethod(InMemorySessionRegistry::class, 'clientsOf')]
final class ClientsOfTest extends TestCase
{
    public function testItKnowsNoClientsOfAnUnknownSession(): void
    {
        // Arrange
        $registry = new InMemorySessionRegistry();

        // Act
        $clients = $registry->clientsOf('nope');

        // Assert
        self::assertSame([], $clients);
    }
}
