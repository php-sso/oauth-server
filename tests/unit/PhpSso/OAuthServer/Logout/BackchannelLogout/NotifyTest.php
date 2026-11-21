<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Logout\BackchannelLogout;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Logout\BackchannelLogout;
use PhpSso\OAuthServer\Logout\LogoutDelivery;
use PhpSso\OAuthServer\Tests\Support\CapturingHandler;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(BackchannelLogout::class, 'notify')]
final class NotifyTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
        $this->t->sessions->register('session-1', 'web');
    }

    public function testItPostsASignedLogoutTokenToTheClient(): void
    {
        // Act
        $deliveries = $this->notify();

        // Assert
        self::assertCount(1, $this->t->http->sent);
        $request = $this->t->http->sent[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://app.example/backchannel-logout', (string) $request->getUri());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $request->getHeaderLine('Cache-Control'));
        self::assertCount(1, $deliveries);
        self::assertTrue($deliveries[0]->delivered);
        self::assertSame(200, $deliveries[0]->status);
        self::assertSame('web', $deliveries[0]->clientId);
    }

    public function testTheLogoutTokenFollowsTheSpec(): void
    {
        // Act
        $this->notify();

        // Assert
        $jwt = $this->t->http->logoutToken($this->t->http->sent[0]);
        $decoded = (new JwtDecoder($this->t->keys))->decode($jwt);
        self::assertSame('logout+jwt', $decoded['header']['typ']);
        $claims = $decoded['claims'];
        self::assertSame(TestServer::ISSUER, $claims['iss']);
        self::assertSame('web', $claims['aud']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('session-1', $claims['sid']);
        self::assertSame(['http://schemas.openid.net/event/backchannel-logout' => []], $claims['events']);
        self::assertArrayNotHasKey('nonce', $claims);
        self::assertIsString($claims['jti']);
        self::assertSame($this->t->clock->timestamp() + 120, $claims['exp']);
        (new ClaimsValidator($this->t->clock, TestServer::ISSUER))->validate($claims, 'web');
    }

    public function testTheLogoutTokenCannotBeUsedAsAnAccessToken(): void
    {
        // Arrange
        $this->notify();
        $jwt = $this->t->http->logoutToken($this->t->http->sent[0]);
        $request = (new ServerRequest([], [], '/api', 'GET'))->withHeader('Authorization', 'Bearer ' . $jwt);

        // Act
        $response = $this->t->server->bearerTokenMiddleware()->process($request, new CapturingHandler());

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testItSkipsClientsWithoutALogoutUri(): void
    {
        // Arrange
        $this->t->sessions->register('session-1', 'spa');
        $this->t->sessions->register('session-1', 'ghost');

        // Act
        $deliveries = $this->notify();

        // Assert
        self::assertCount(1, $deliveries);
        self::assertCount(1, $this->t->http->sent);
    }

    public function testItReportsAClientThatAnswersWithAnError(): void
    {
        // Arrange
        $this->t->http->answers['https://app.example/backchannel-logout'] = 400;

        // Act
        $deliveries = $this->notify();

        // Assert
        self::assertFalse($deliveries[0]->delivered);
        self::assertSame(400, $deliveries[0]->status);
        self::assertNotNull($deliveries[0]->error);
    }

    public function testItReportsAClientThatCannotBeReachedInsteadOfFailing(): void
    {
        // Arrange
        $this->t->http->answers['https://app.example/backchannel-logout'] = 'Connection refused';

        // Act
        $deliveries = $this->notify();

        // Assert
        self::assertFalse($deliveries[0]->delivered);
        self::assertNull($deliveries[0]->status);
        self::assertSame('Connection refused', $deliveries[0]->error);
    }

    public function testItTreatsAnyTwoHundredAsDelivered(): void
    {
        // Arrange
        $this->t->http->answers['https://app.example/backchannel-logout'] = 204;

        // Act
        $deliveries = $this->notify();

        // Assert
        self::assertTrue($deliveries[0]->delivered);
    }

    public function testItNeverSendsToAUriThatIsNotHttp(): void
    {
        // Arrange
        $this->t->clients->add(new TestClient('odd', [], true, [], [], 'x', 'file:///etc/passwd'));
        $this->t->sessions->register('session-2', 'odd');

        // Act
        $deliveries = $this->t->server->logoutService()->sessionEnded('session-2', 'user-1');

        // Assert
        self::assertFalse($deliveries[0]->delivered);
        self::assertSame([], $this->t->http->sent);
    }

    /** @return list<LogoutDelivery> */
    private function notify(): array
    {
        return $this->t->server->logoutService()->sessionEnded('session-1', 'user-1');
    }
}
