<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Device\DeviceVerifier;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Device\DeviceVerifier;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\DeviceStatus;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Token\TokenHash;

#[CoversMethod(DeviceVerifier::class, 'deny')]
final class DenyTest extends TestCase
{
    public function testItMarksTheRequestDenied(): void
    {
        // Arrange
        $userCode = $this->startDevice();

        // Act
        $this->t->server->deviceVerifier()->deny($userCode);

        // Assert
        $record = $this->t->devices->findByUserCodeHash(TokenHash::of(str_replace('-', '', $userCode)));
        self::assertSame(DeviceStatus::Denied, $record?->status);
    }

    public function testItRefusesAnUnknownCode(): void
    {
        // Arrange
        $this->expectException(OAuthException::class);

        // Act
        $this->t->server->deviceVerifier()->deny('BBBB-BBBB');
    }

    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    private function startDevice(): string
    {
        $request = (new ServerRequest([], [], '/device_authorization', 'POST'))->withParsedBody(['client_id' => 'tv', 'scope' => 'openid profile']);
        $body = $this->t->json($this->t->server->deviceAuthorizationHandler()->handle($request));

        return $this->t->str($body, 'user_code');
    }
}
