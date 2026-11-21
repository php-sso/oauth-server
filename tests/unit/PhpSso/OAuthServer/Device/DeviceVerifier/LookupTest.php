<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Device\DeviceVerifier;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Device\DeviceVerifier;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(DeviceVerifier::class, 'lookup')]
final class LookupTest extends TestCase
{
    public function testItShowsWhoIsAskingAndForWhat(): void
    {
        // Arrange
        $userCode = $this->startDevice();

        // Act
        $pending = $this->t->server->deviceVerifier()->lookup($userCode);

        // Assert
        self::assertNotNull($pending);
        self::assertSame('tv', $pending->client->id());
        self::assertSame(['openid', 'profile'], $pending->scopes);
        self::assertSame($userCode, $pending->userCode);
    }

    public function testItIgnoresCaseSpacesAndDashesInWhatWasTyped(): void
    {
        // Arrange
        $userCode = $this->startDevice();
        $typed = ' ' . strtolower(str_replace('-', ' ', $userCode)) . ' ';

        // Act
        $pending = $this->t->server->deviceVerifier()->lookup($typed);

        // Assert
        self::assertNotNull($pending);
        self::assertSame($userCode, $pending->userCode);
    }

    public function testItKnowsNothingOfAnUnknownCode(): void
    {
        // Act
        $pending = $this->t->server->deviceVerifier()->lookup('BBBB-BBBB');

        // Assert
        self::assertNull($pending);
    }

    public function testItKnowsNothingOfAnExpiredCode(): void
    {
        // Arrange
        $userCode = $this->startDevice();
        $this->t->clock->advance(601);

        // Act
        $pending = $this->t->server->deviceVerifier()->lookup($userCode);

        // Assert
        self::assertNull($pending);
    }

    public function testItKnowsNothingOfACodeThatWasAlreadyAnswered(): void
    {
        // Arrange
        $userCode = $this->startDevice();
        $this->t->server->deviceVerifier()->deny($userCode);

        // Act
        $pending = $this->t->server->deviceVerifier()->lookup($userCode);

        // Assert
        self::assertNull($pending);
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
