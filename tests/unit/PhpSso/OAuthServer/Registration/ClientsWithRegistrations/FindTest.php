<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Registration\ClientsWithRegistrations;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Registration\ClientsWithRegistrations;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(ClientsWithRegistrations::class, 'find')]
#[CoversMethod(ClientsWithRegistrations::class, 'verifySecret')]
final class FindTest extends TestCase
{
    public function testItFindsAConfiguredClientAndARegisteredOne(): void
    {
        // Arrange
        $t = new TestServer();
        $registered = $t->registered();
        $clients = new ClientsWithRegistrations($t->clients, $t->registrations);

        // Act
        $configured = $clients->find('web');
        $dynamic = $clients->find($t->str($registered, 'client_id'));

        // Assert
        self::assertSame('web', $configured?->id());
        self::assertSame($registered['client_id'], $dynamic?->id());
        self::assertNull($clients->find('nobody'));
    }

    public function testItChecksSecretsOfBothKinds(): void
    {
        // Arrange
        $t = new TestServer();
        $registered = $t->registered(['redirect_uris' => [TestServer::REDIRECT]]);
        $clients = new ClientsWithRegistrations($t->clients, $t->registrations);
        $dynamic = $clients->find($t->str($registered, 'client_id'));
        $configured = $clients->find('web');
        self::assertNotNull($dynamic);
        self::assertNotNull($configured);

        // Act
        $results = [
            $clients->verifySecret($dynamic, $t->str($registered, 'client_secret')),
            $clients->verifySecret($dynamic, 'wrong'),
            $clients->verifySecret($configured, 's3cret'),
            $clients->verifySecret($configured, 'wrong'),
        ];

        // Assert
        self::assertSame([true, false, true, false], $results);
    }
}
