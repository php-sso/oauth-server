<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\AuthorizationServer;

use LogicException;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\AuthorizationServer;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(AuthorizationServer::class, 'registrationHandler')]
#[CoversMethod(AuthorizationServer::class, 'clientConfigurationHandler')]
#[CoversMethod(AuthorizationServer::class, 'registrationMiddleware')]
final class RegistrationHandlerTest extends TestCase
{
    public function testRegistrationIsOffUnlessAStoreIsGiven(): void
    {
        // Arrange
        $t = new TestServer(registration: false);
        $this->expectException(LogicException::class);

        // Act
        $t->server->registrationHandler();
    }

    public function testTheMiddlewareIsOffToo(): void
    {
        // Arrange
        $t = new TestServer(registration: false);
        $this->expectException(LogicException::class);

        // Act
        $t->server->registrationMiddleware();
    }

    public function testTheConfigurationHandlerIsOffToo(): void
    {
        // Arrange
        $t = new TestServer(registration: false);
        $this->expectException(LogicException::class);

        // Act
        $t->server->clientConfigurationHandler();
    }
}
