<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\ClientConfigurationHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\ClientConfigurationHandler;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(ClientConfigurationHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testItReadsTheRegistration(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT], 'client_name' => 'First']);

        // Act
        $response = $this->t->configure('GET', $this->t->str($registered, 'client_id'), $this->t->str($registered, 'registration_access_token'));

        // Assert
        $body = $this->t->json($response);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame($registered['client_id'], $body['client_id']);
        self::assertSame('First', $body['client_name']);
        self::assertSame($registered['registration_client_uri'], $body['registration_client_uri']);
        self::assertArrayNotHasKey('client_secret', $body);
        self::assertArrayNotHasKey('registration_access_token', $body);
    }

    public function testItTakesTheClientIdFromTheRequestAttribute(): void
    {
        // Arrange
        $registered = $this->t->registered();
        $request = (new ServerRequest([], [], '/anything', 'GET'))
            ->withAttribute(ClientConfigurationHandler::CLIENT_ID, $this->t->str($registered, 'client_id'))
            ->withHeader('Authorization', 'Bearer ' . $this->t->str($registered, 'registration_access_token'));

        // Act
        $response = $this->t->server->clientConfigurationHandler()->handle($request);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testItReplacesTheRegistration(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'client_name' => 'Old']);
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'redirect_uris' => ['https://other.example/cb'], 'token_endpoint_auth_method' => 'none', 'client_name' => 'New',
        ]);

        // Assert
        $body = $this->t->json($response);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('New', $body['client_name']);
        self::assertSame(['https://other.example/cb'], $body['redirect_uris']);
        $stored = $this->t->registrations->find($id);
        self::assertNotNull($stored);
        self::assertSame(['https://other.example/cb'], $stored->redirectUris());
    }

    public function testFieldsLeftOutOfAReplacementFallBackToTheirDefaults(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'client_name' => 'Old']);
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none',
        ]);

        // Assert
        self::assertArrayNotHasKey('client_name', $this->t->json($response));
    }

    public function testChangingAPublicClientToConfidentialIssuesASecret(): void
    {
        // Arrange
        $registered = $this->t->registered();
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'client_secret_post',
        ]);

        // Assert
        $body = $this->t->json($response);
        $stored = $this->t->registrations->find($id);
        self::assertNotNull($stored);
        self::assertTrue($stored->verifySecret($this->t->str($body, 'client_secret')));
    }

    public function testChangingAClientToPublicDropsItsSecret(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT]]);
        $id = $this->t->str($registered, 'client_id');

        // Act
        $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none',
        ]);

        // Assert
        self::assertNull($this->t->registrations->find($id)?->secretHash);
    }

    public function testTheClientCannotChooseItsOwnSecret(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT]]);
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'client_secret' => 'my-own-secret', 'redirect_uris' => [TestServer::REDIRECT],
        ]);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testAReplacementKeepsTheCurrentSecretWhenItIsRepeated(): void
    {
        // Arrange
        $registered = $this->t->registered(['redirect_uris' => [TestServer::REDIRECT]]);
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'client_secret' => $this->t->str($registered, 'client_secret'), 'redirect_uris' => [TestServer::REDIRECT],
        ]);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($this->t->registrations->find($id)?->verifySecret($this->t->str($registered, 'client_secret')));
    }

    public function testAReplacementMustNameTheSameClient(): void
    {
        // Arrange
        $registered = $this->t->registered();

        // Act
        $response = $this->t->configure('PUT', $this->t->str($registered, 'client_id'), $this->t->str($registered, 'registration_access_token'), [
            'client_id' => 'someone-else', 'redirect_uris' => [TestServer::REDIRECT],
        ]);

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testAReplacementIsValidatedLikeARegistration(): void
    {
        // Arrange
        $registered = $this->t->registered();
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('PUT', $id, $this->t->str($registered, 'registration_access_token'), [
            'client_id' => $id, 'redirect_uris' => ['http://evil.example/cb'],
        ]);

        // Assert
        self::assertSame('invalid_redirect_uri', $this->t->json($response)['error']);
    }

    public function testItDeletesTheClient(): void
    {
        // Arrange
        $registered = $this->t->registered();
        $id = $this->t->str($registered, 'client_id');

        // Act
        $response = $this->t->configure('DELETE', $id, $this->t->str($registered, 'registration_access_token'));

        // Assert
        self::assertSame(204, $response->getStatusCode());
        self::assertSame('', (string) $response->getBody());
        self::assertNull($this->t->registrations->find($id));
        self::assertSame(400, $this->t->authorize(['client_id' => $id])->getStatusCode());
    }

    public function testItNeedsTheRegistrationAccessToken(): void
    {
        // Arrange
        $registered = $this->t->registered();

        // Act
        $response = $this->t->configure('GET', $this->t->str($registered, 'client_id'), null);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', $this->t->json($response)['error']);
    }

    public function testAnotherClientsTokenIsRefused(): void
    {
        // Arrange
        $first = $this->t->registered();
        $second = $this->t->registered();

        // Act
        $response = $this->t->configure('DELETE', $this->t->str($first, 'client_id'), $this->t->str($second, 'registration_access_token'));

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertNotNull($this->t->registrations->find($this->t->str($first, 'client_id')));
    }

    public function testTheRegistrarsAccessTokenCannotManageAClient(): void
    {
        // Arrange
        $registered = $this->t->registered();

        // Act
        $response = $this->t->configure('DELETE', $this->t->str($registered, 'client_id'), $this->t->registrarToken());

        // Assert
        self::assertSame(401, $response->getStatusCode());
    }

    public function testAnUnknownClientLooksLikeAWrongToken(): void
    {
        // Act
        $response = $this->t->configure('GET', 'nobody', 'whatever');

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_token', $this->t->json($response)['error']);
    }

    public function testItRefusesOtherMethods(): void
    {
        // Arrange
        $registered = $this->t->registered();

        // Act
        $response = $this->t->configure('PATCH', $this->t->str($registered, 'client_id'), $this->t->str($registered, 'registration_access_token'));

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }
}
