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

#[CoversMethod(DeviceVerifier::class, 'approve')]
final class ApproveTest extends TestCase
{
    public function testItApprovesTheRequestForThePerson(): void
    {
        // Arrange
        $userCode = $this->startDevice();

        // Act
        $this->t->server->deviceVerifier()->approve($userCode, 'user-1', 'session-1');

        // Assert
        $record = $this->t->devices->findByUserCodeHash(TokenHash::of(str_replace('-', '', $userCode)));
        self::assertSame(DeviceStatus::Approved, $record?->status);
        self::assertSame('user-1', $record->userId);
        self::assertSame('session-1', $record->sessionId);
    }

    public function testItRefusesAPersonTheClientMayNotServe(): void
    {
        // Arrange
        $userCode = $this->startDevice();
        $this->t->policy->denied['tv|user-1'] = true;
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('access_denied');

        // Act
        $this->t->server->deviceVerifier()->approve($userCode, 'user-1', null);
    }

    public function testItRefusesAnUnknownCode(): void
    {
        // Arrange
        $this->expectException(OAuthException::class);

        // Act
        $this->t->server->deviceVerifier()->approve('BBBB-BBBB', 'user-1', null);
    }

    public function testItRefusesToApproveTheSameRequestTwice(): void
    {
        // Arrange
        $userCode = $this->startDevice();
        $this->t->server->deviceVerifier()->approve($userCode, 'user-1', null);
        $this->expectException(OAuthException::class);

        // Act
        $this->t->server->deviceVerifier()->approve($userCode, 'user-2', null);
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
