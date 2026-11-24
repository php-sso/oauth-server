<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Registration\RegistrarPolicy;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\ClientConfigurationHandler;
use PhpSso\OAuthServer\Endpoint\ClientRegistrationHandler;
use PhpSso\OAuthServer\Tests\Support\TestRegistrarPolicy;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversClass(ClientRegistrationHandler::class)]
#[CoversClass(ClientConfigurationHandler::class)]
final class HandlersTest extends TestCase
{
    /** @param array<string, list<string>|null> $registrars */
    private function server(array $registrars): TestServer
    {
        return new TestServer(registrarPolicy: new TestRegistrarPolicy($registrars));
    }

    public function testAClientTheServerDoesNotKnowAsARegistrarIsRefusedEvenWithAValidToken(): void
    {
        // Arrange
        $t = $this->server([]);

        // Act
        $response = $t->register(['redirect_uris' => [TestServer::REDIRECT]]);

        // Assert
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('access_denied', $t->json($response)['error']);
    }

    public function testARegistrarWithoutALimitGetsTheDefaults(): void
    {
        // Arrange
        $t = $this->server(['registrar' => null]);

        // Act
        $response = $t->register(['redirect_uris' => [TestServer::REDIRECT], 'scope' => 'openid email']);

        // Assert
        self::assertSame(201, $response->getStatusCode());
    }

    public function testTheScopesOfTheRegistrarLimitWhatItsAppsGet(): void
    {
        // Arrange
        $t = $this->server(['registrar' => ['openid', 'api']]);

        // Act
        $allowed = $t->register(['redirect_uris' => [TestServer::REDIRECT], 'scope' => 'openid api']);
        $refused = $t->register(['redirect_uris' => [TestServer::REDIRECT], 'scope' => 'openid email']);

        // Assert
        self::assertSame(201, $allowed->getStatusCode());
        self::assertSame('invalid_client_metadata', $t->json($refused)['error']);
    }

    public function testTheRegistrationScopeIsNeverGrantedEvenWhenThePolicyListsIt(): void
    {
        // Arrange
        $t = $this->server(['registrar' => ['openid', 'client:register']]);

        // Act
        $response = $t->register(['redirect_uris' => [TestServer::REDIRECT], 'scope' => 'client:register']);

        // Assert
        self::assertSame('invalid_client_metadata', $t->json($response)['error']);
    }

    public function testAnUpdateStaysWithinTheScopesOfTheRegistrarThatRegisteredTheApp(): void
    {
        // Arrange
        $policy = new TestRegistrarPolicy(['registrar' => ['openid', 'profile']]);
        $t = new TestServer(registrarPolicy: $policy);
        $registered = $t->json($t->register(['redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'scope' => 'openid']));
        $id = $t->str($registered, 'client_id');

        // Act
        $within = $t->configure('PUT', $id, $t->str($registered, 'registration_access_token'), ['client_id' => $id, 'redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'scope' => 'openid profile']);
        $beyond = $t->configure('PUT', $id, $t->str($registered, 'registration_access_token'), ['client_id' => $id, 'redirect_uris' => [TestServer::REDIRECT], 'token_endpoint_auth_method' => 'none', 'scope' => 'openid email']);

        // Assert
        self::assertSame(200, $within->getStatusCode());
        self::assertSame('invalid_client_metadata', $t->json($beyond)['error']);
    }

    public function testAnAppCanStillManageItselfAfterItsRegistrarLostTheRight(): void
    {
        // Arrange
        $policy = new TestRegistrarPolicy(['registrar' => null]);
        $t = new TestServer(registrarPolicy: $policy);
        $registered = $t->json($t->register(['redirect_uris' => [TestServer::REDIRECT]]));
        $policy->registrars = [];

        // Act
        $response = $t->configure('GET', $t->str($registered, 'client_id'), $t->str($registered, 'registration_access_token'));

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testDiscoveryOnlyAdvertisesTheEndpointWhileAClientMayRegister(): void
    {
        // Arrange
        $none = $this->server([]);
        $some = $this->server(['registrar' => null]);

        // Act
        $without = $none->json($none->server->discoveryHandler()->handle(new ServerRequest()));
        $with = $some->json($some->server->discoveryHandler()->handle(new ServerRequest()));

        // Assert
        self::assertArrayNotHasKey('registration_endpoint', $without);
        self::assertSame('https://sso.example.com/register', $with['registration_endpoint']);
    }
}
