<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Client\ClientAuthenticator;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Tests\Support\TimingAwareClientRepository;

#[CoversMethod(ClientAuthenticator::class, 'authenticate')]
final class AuthenticateTimingTest extends TestCase
{
    public function testAnUnknownClientCostsTheSameVerificationTimeAsAWrongSecret(): void
    {
        // Arrange
        $clients = new TimingAwareClientRepository((new TestServer())->clients);
        $auth = new ClientAuthenticator($clients);
        $request = $this->form(['client_id' => 'nobody', 'client_secret' => 'guess']);

        // Act
        try {
            $auth->authenticate($request, Params::fromBody($request));
            self::fail('An unknown client must be refused.');
        } catch (OAuthException) {
        }

        // Assert
        self::assertSame(['guess'], $clients->spentOn);
    }

    public function testAKnownClientDoesNotTriggerTheExtraWork(): void
    {
        // Arrange
        $clients = new TimingAwareClientRepository((new TestServer())->clients);
        $auth = new ClientAuthenticator($clients);
        $request = $this->form(['client_id' => 'web', 'client_secret' => 's3cret']);

        // Act
        $auth->authenticate($request, Params::fromBody($request));

        // Assert
        self::assertSame([], $clients->spentOn);
    }

    /** @param array<string, string> $body */
    private function form(array $body): ServerRequest
    {
        return (new ServerRequest([], [], null, 'POST'))->withParsedBody($body);
    }
}
