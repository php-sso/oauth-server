<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\DeviceAuthorizationHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\DeviceAuthorizationHandler;
use PhpSso\OAuthServer\Grant\DeviceStatus;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Token\TokenHash;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(DeviceAuthorizationHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testItIssuesADeviceCodeAndAUserCode(): void
    {
        // Act
        $response = $this->request(['client_id' => 'tv', 'scope' => 'openid profile']);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = $this->t->json($response);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $this->t->str($body, 'device_code'));
        self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/', $this->t->str($body, 'user_code'));
        self::assertSame(600, $body['expires_in']);
        self::assertSame(5, $body['interval']);
    }

    public function testItPointsThePersonToTheVerificationPageWithTheCodeFilledIn(): void
    {
        // Act
        $body = $this->t->json($this->request(['client_id' => 'tv', 'scope' => 'openid']));

        // Assert
        self::assertSame('https://sso.example.com/device', $body['verification_uri']);
        self::assertSame('https://sso.example.com/device?user_code=' . $this->t->str($body, 'user_code'), $body['verification_uri_complete']);
    }

    public function testItStoresOnlyHashesOfTheCodes(): void
    {
        // Act
        $body = $this->t->json($this->request(['client_id' => 'tv', 'scope' => 'openid']));

        // Assert
        $deviceCode = $this->t->str($body, 'device_code');
        self::assertNull($this->t->devices->findByDeviceCodeHash($deviceCode));
        $record = $this->t->devices->findByDeviceCodeHash(TokenHash::of($deviceCode));
        self::assertNotNull($record);
        self::assertSame('tv', $record->clientId);
        self::assertSame(['openid'], $record->scopes);
        self::assertSame(DeviceStatus::Pending, $record->status);
    }

    public function testEveryRequestGetsItsOwnCodes(): void
    {
        // Act
        $first = $this->t->json($this->request(['client_id' => 'tv', 'scope' => 'openid']));
        $second = $this->t->json($this->request(['client_id' => 'tv', 'scope' => 'openid']));

        // Assert
        self::assertNotSame($first['device_code'], $second['device_code']);
        self::assertNotSame($first['user_code'], $second['user_code']);
    }

    public function testAConfidentialClientMustAuthenticate(): void
    {
        // Arrange
        $this->t->clients->add(new TestClient('kiosk', [], true, [GrantType::DeviceCode], ['openid'], 'k'));

        // Act
        $anonymous = $this->request(['client_id' => 'kiosk', 'scope' => 'openid']);

        // Assert
        self::assertSame('invalid_client', $this->t->json($anonymous)['error']);
    }

    public function testItRefusesAClientThatMayNotUseTheDeviceFlow(): void
    {
        // Act
        $response = $this->request(['client_id' => 'spa', 'scope' => 'openid']);

        // Assert
        self::assertSame('unauthorized_client', $this->t->json($response)['error']);
    }

    public function testItRefusesAScopeTheClientMayNotHave(): void
    {
        // Act
        $response = $this->request(['client_id' => 'tv', 'scope' => 'openid email']);

        // Assert
        self::assertSame('invalid_scope', $this->t->json($response)['error']);
    }

    public function testItOnlyAcceptsPost(): void
    {
        // Act
        $response = $this->t->server->deviceAuthorizationHandler()->handle(new ServerRequest([], [], '/device_authorization', 'GET'));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    /** @param array<string, string> $form */
    private function request(array $form): ResponseInterface
    {
        $request = (new ServerRequest([], [], '/device_authorization', 'POST'))->withParsedBody($form);

        return $this->t->server->deviceAuthorizationHandler()->handle($request);
    }
}
