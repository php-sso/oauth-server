<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\IntrospectionHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\IntrospectionHandler;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(IntrospectionHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
        $this->t->clients->add(new TestClient('api', [], true, [], [], 'api-secret')); // a resource server
    }

    public function testItDescribesAnActiveAccessToken(): void
    {
        // Arrange
        $access = $this->t->str($this->t->signIn(), 'access_token');

        // Act
        $body = $this->t->json($this->introspect($access));

        // Assert
        self::assertTrue($body['active']);
        self::assertSame('openid profile', $body['scope']);
        self::assertSame('web', $body['client_id']);
        self::assertSame('Bearer', $body['token_type']);
        self::assertSame('user-1', $body['sub']);
        self::assertSame(TestServer::ISSUER, $body['iss']);
        self::assertSame('session-1', $body['sid']);
        self::assertSame($this->t->clock->timestamp() + 3600, $body['exp']);
        self::assertIsString($body['jti']);
    }

    public function testItDescribesAnActiveRefreshTokenToItsOwnClientOnly(): void
    {
        // Arrange
        $refresh = $this->t->str($this->t->signIn(), 'refresh_token');

        // Act
        $own = $this->t->json($this->introspect($refresh, ['web', 's3cret']));
        $foreign = $this->t->json($this->introspect($refresh));

        // Assert
        self::assertTrue($own['active']);
        self::assertSame('user-1', $own['sub']);
        self::assertSame(['active' => false], $foreign);
    }

    public function testEveryKindOfFailureLooksTheSame(): void
    {
        // Arrange
        $tokens = $this->t->signIn();
        $expired = $this->t->str($tokens, 'access_token');
        $this->t->clock->advance(3700);

        // Act
        $garbage = $this->t->json($this->introspect('not-a-token'));
        $old = $this->t->json($this->introspect($expired));

        // Assert
        self::assertSame(['active' => false], $garbage);
        self::assertSame(['active' => false], $old);
    }

    public function testARevokedTokenIsInactiveAtOnce(): void
    {
        // Arrange
        $tokens = $this->t->signIn();
        $this->t->server->logoutService()->sessionEnded('session-1', 'user-1');

        // Act
        $access = $this->t->json($this->introspect($this->t->str($tokens, 'access_token')));
        $refresh = $this->t->json($this->introspect($this->t->str($tokens, 'refresh_token'), ['web', 's3cret']));

        // Assert
        self::assertSame(['active' => false], $access);
        self::assertSame(['active' => false], $refresh);
    }

    public function testAnIdTokenIsNotAnActiveAccessToken(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $body = $this->t->json($this->introspect($idToken));

        // Assert
        self::assertSame(['active' => false], $body);
    }

    public function testTheCallerMustAuthenticate(): void
    {
        // Act
        $response = $this->introspect('x', ['api', 'wrong']);

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testAPublicClientMayNotIntrospect(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/introspect', 'POST'))->withParsedBody(['token' => 'x', 'client_id' => 'spa']);

        // Act
        $response = $this->t->server->introspectionHandler()->handle($request);

        // Assert
        self::assertSame('invalid_client', $this->t->json($response)['error']);
    }

    public function testItNeedsAToken(): void
    {
        // Act
        $response = $this->t->server->introspectionHandler()->handle($this->request([], ['api', 'api-secret']));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testItOnlyAcceptsPost(): void
    {
        // Act
        $response = $this->t->server->introspectionHandler()->handle(new ServerRequest([], [], '/introspect', 'GET'));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    /**
     * @param array<string, string> $form
     * @param array{string, string} $basic
     */
    private function request(array $form, array $basic): ServerRequest
    {
        return (new ServerRequest([], [], '/introspect', 'POST'))
            ->withHeader('Authorization', 'Basic ' . base64_encode($basic[0] . ':' . $basic[1]))
            ->withParsedBody($form);
    }

    /** @param array{string, string} $as */
    private function introspect(string $token, array $as = ['api', 'api-secret']): ResponseInterface
    {
        return $this->t->server->introspectionHandler()->handle($this->request(['token' => $token], $as));
    }
}
