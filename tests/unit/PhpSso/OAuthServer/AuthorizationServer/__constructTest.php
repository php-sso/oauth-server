<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\AuthorizationServer;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\AuthorizationServer;
use PhpSso\OAuthServer\Tests\Support\PageErrorResponder;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(AuthorizationServer::class, '__construct')]
final class __constructTest extends TestCase
{
    public function testBrowserErrorsAreAnsweredWithTheBrowserResponderAtTheAuthorizationEndpoint(): void
    {
        // Arrange
        $t = new TestServer(browserErrors: new PageErrorResponder());

        // Act
        $response = $t->authorize(['redirect_uri' => 'https://evil.example/cb']);

        // Assert
        self::assertStringStartsWith('text/html', $response->getHeaderLine('Content-Type'));
        self::assertSame(400, $response->getStatusCode());
    }

    public function testBrowserErrorsAreAnsweredWithTheBrowserResponderAtTheEndSessionEndpoint(): void
    {
        // Arrange
        $t = new TestServer(browserErrors: new PageErrorResponder());
        $request = (new ServerRequest([], [], null, 'GET'))->withQueryParams(['id_token_hint' => 'garbage']);

        // Act
        $response = $t->server->endSessionHandler()->handle($request);

        // Assert
        self::assertStringStartsWith('text/html', $response->getHeaderLine('Content-Type'));
    }

    public function testTheTokenEndpointKeepsAnsweringWithJson(): void
    {
        // Arrange
        $t = new TestServer(browserErrors: new PageErrorResponder());
        $request = (new ServerRequest([], [], null, 'GET'));

        // Act
        $response = $t->server->tokenHandler()->handle($request);

        // Assert
        self::assertStringStartsWith('application/json', $response->getHeaderLine('Content-Type'));
    }

    public function testWithoutABrowserResponderTheAuthorizationEndpointAnswersWithJson(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $response = $t->authorize(['redirect_uri' => 'https://evil.example/cb']);

        // Assert
        self::assertStringStartsWith('application/json', $response->getHeaderLine('Content-Type'));
    }
}
