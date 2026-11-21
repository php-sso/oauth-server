<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Client\ClientAuthenticator;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(ClientAuthenticator::class, 'authenticate')]
final class AuthenticateTest extends TestCase
{
    private ClientAuthenticator $auth;

    protected function setUp(): void
    {
        $t = new TestServer();
        $t->clients->add(new TestClient('we:ird', [], true, [], [], 'p@ss word'));
        $this->auth = new ClientAuthenticator($t->clients);
    }

    public function testItAuthenticatesAConfidentialClientWithBasicCredentials(): void
    {
        // Arrange
        $request = $this->basic('web', 's3cret');

        // Act
        $client = $this->auth->authenticate($request, Params::fromBody($request));

        // Assert
        self::assertSame('web', $client->id());
    }

    public function testItUrlDecodesBasicCredentialsAsTheRfcRequires(): void
    {
        // Arrange
        $request = $this->basic('we:ird', 'p@ss word');

        // Act
        $client = $this->auth->authenticate($request, Params::fromBody($request));

        // Assert
        self::assertSame('we:ird', $client->id());
    }

    public function testItAuthenticatesWithCredentialsInTheBody(): void
    {
        // Arrange
        $request = $this->form(['client_id' => 'web', 'client_secret' => 's3cret']);

        // Act
        $client = $this->auth->authenticate($request, Params::fromBody($request));

        // Assert
        self::assertSame('web', $client->id());
    }

    public function testItIdentifiesAPublicClientByItsIdAlone(): void
    {
        // Arrange
        $request = $this->form(['client_id' => 'spa']);

        // Act
        $client = $this->auth->authenticate($request, Params::fromBody($request));

        // Assert
        self::assertFalse($client->isConfidential());
    }

    #[DataProvider('failures')]
    public function testItRejectsEverythingElseTheSameWay(ServerRequest $request, string $error): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage($error);

        // Act
        $this->auth->authenticate($request, Params::fromBody($request));
    }

    /** @return array<string, array{ServerRequest, string}> */
    public static function failures(): array
    {
        $form = static fn (array $body, ?string $header = null): ServerRequest => ($header === null ? new ServerRequest([], [], '/token', 'POST') : (new ServerRequest([], [], '/token', 'POST'))->withHeader('Authorization', $header))->withParsedBody($body);

        return [
            'no credentials at all' => [$form([]), 'invalid_client'],
            'unknown client' => [$form(['client_id' => 'nobody', 'client_secret' => 'x']), 'invalid_client'],
            'wrong secret' => [$form(['client_id' => 'web', 'client_secret' => 'wrong']), 'invalid_client'],
            'confidential client without a secret' => [$form(['client_id' => 'web']), 'invalid_client'],
            'public client that sends a secret' => [$form(['client_id' => 'spa', 'client_secret' => 'x']), 'invalid_client'],
            'basic header that is not base64' => [$form([], 'Basic !!!'), 'invalid_client'],
            'basic header without a colon' => [$form([], 'Basic ' . base64_encode('web')), 'invalid_client'],
            'secret in both header and body' => [$form(['client_secret' => 's3cret'], 'Basic ' . base64_encode('web:s3cret')), 'invalid_request'],
            'body client id differs from header' => [$form(['client_id' => 'spa'], 'Basic ' . base64_encode('web:s3cret')), 'invalid_request'],
        ];
    }

    private function basic(string $id, string $secret): ServerRequest
    {
        return (new ServerRequest([], [], '/token', 'POST'))
            ->withHeader('Authorization', 'Basic ' . base64_encode(urlencode($id) . ':' . urlencode($secret)))
            ->withParsedBody([]);
    }

    /** @param array<string, string> $body */
    private function form(array $body): ServerRequest
    {
        return (new ServerRequest([], [], '/token', 'POST'))->withParsedBody($body);
    }
}
