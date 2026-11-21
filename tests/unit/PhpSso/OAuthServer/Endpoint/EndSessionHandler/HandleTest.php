<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\EndSessionHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\AuthorizationHandler;
use PhpSso\OAuthServer\Endpoint\EndSessionHandler;
use PhpSso\OAuthServer\Tests\Support\JwtForge;
use PhpSso\OAuthServer\Tests\Support\TestKeys;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(EndSessionHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testAValidHintEndsTheBrowsersSessionWithoutAsking(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $response = $this->endSession(['id_token_hint' => $idToken], signedIn: true);

        // Assert
        self::assertSame('signed out', (string) $response->getBody());
        self::assertSame(['session-1'], $this->t->terminator->terminated);
        self::assertSame('session-1', $this->t->logoutUi->endedSessionId);
    }

    public function testEndingASessionRevokesItsTokensAndNotifiesTheClients(): void
    {
        // Arrange
        $tokens = $this->t->signIn();

        // Act
        $this->endSession(['id_token_hint' => $this->t->str($tokens, 'id_token')], signedIn: true);

        // Assert
        self::assertCount(1, $this->t->http->sent);
        $refresh = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($tokens, 'refresh_token')], ['web', 's3cret']);
        self::assertSame('invalid_grant', $this->t->json($refresh)['error']);
    }

    public function testItRedirectsToARegisteredPostLogoutUriWithTheState(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $response = $this->endSession([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => 'https://app.example/signed-out',
            'state' => 'abc 1',
        ], signedIn: true);

        // Assert
        self::assertSame(302, $response->getStatusCode());
        self::assertSame('https://app.example/signed-out?state=abc%201', $response->getHeaderLine('Location'));
    }

    public function testItRefusesARedirectUriThatIsNotRegistered(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $response = $this->endSession(['id_token_hint' => $idToken, 'post_logout_redirect_uri' => 'https://evil.example/'], signedIn: true);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame([], $this->t->terminator->terminated);
    }

    public function testItRefusesARedirectUriForAClientThatNeverSentOne(): void
    {
        // Act
        $response = $this->endSession(['client_id' => 'spa', 'post_logout_redirect_uri' => 'https://app.example/signed-out'], signedIn: true);

        // Assert
        self::assertSame(400, $response->getStatusCode());
    }

    public function testWithoutAHintItAsksFirstAndKeepsTheSession(): void
    {
        // Act
        $response = $this->endSession(['client_id' => 'web', 'post_logout_redirect_uri' => 'https://app.example/signed-out', 'state' => 's'], signedIn: true);

        // Assert
        self::assertSame('confirm logout', (string) $response->getBody());
        self::assertSame(['client_id' => 'web', 'post_logout_redirect_uri' => 'https://app.example/signed-out', 'state' => 's'], $this->t->logoutUi->confirmFields);
        self::assertSame('web', $this->t->logoutUi->clientName);
        self::assertSame([], $this->t->terminator->terminated);
    }

    public function testAConfirmedPostEndsTheSession(): void
    {
        // Act
        $response = $this->endSession(['client_id' => 'web', 'post_logout_redirect_uri' => 'https://app.example/signed-out', 'confirmed' => '1'], signedIn: true, post: true);

        // Assert
        self::assertSame(302, $response->getStatusCode());
        self::assertSame(['session-1'], $this->t->terminator->terminated);
    }

    public function testAGetCannotConfirmOnItsOwn(): void
    {
        // Act
        $response = $this->endSession(['confirmed' => '1'], signedIn: true);

        // Assert
        self::assertSame('confirm logout', (string) $response->getBody());
        self::assertSame([], $this->t->terminator->terminated);
    }

    public function testNothingHappensWhenNobodyIsSignedInAndThereIsNoHint(): void
    {
        // Act
        $response = $this->endSession([], signedIn: false);

        // Assert
        self::assertSame('signed out', (string) $response->getBody());
        self::assertSame([], $this->t->terminator->terminated);
        self::assertNull($this->t->logoutUi->endedSessionId);
    }

    public function testAHintStillEndsItsSessionWhenTheBrowserIsNotSignedIn(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $this->endSession(['id_token_hint' => $idToken], signedIn: false);

        // Assert
        self::assertSame(['session-1'], $this->t->terminator->terminated);
    }

    public function testAHintNamingAnotherSessionEndsThatSessionNotTheBrowsersOwn(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token'); // session-1

        // Act
        $this->endSession(['id_token_hint' => $idToken], signedIn: true, sessionId: 'session-2');

        // Assert
        self::assertSame(['session-1'], $this->t->terminator->terminated);
        self::assertSame('session-1', $this->t->logoutUi->endedSessionId);
    }

    public function testItAcceptsAnExpiredIdTokenAsAHint(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');
        $this->t->clock->advance(86_400);

        // Act
        $response = $this->endSession(['id_token_hint' => $idToken], signedIn: true);

        // Assert
        self::assertSame('signed out', (string) $response->getBody());
        self::assertSame(['session-1'], $this->t->terminator->terminated);
    }

    #[DataProvider('badHints')]
    public function testItRefusesAHintThatIsNotOurIdToken(string $hint): void
    {
        // Act
        $response = $this->endSession(['id_token_hint' => $hint], signedIn: true);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertSame([], $this->t->terminator->terminated);
    }

    /** @return array<string, array{string}> */
    public static function badHints(): array
    {
        $forged = JwtForge::rs256(['alg' => 'RS256', 'kid' => 'key-1'], ['iss' => TestServer::ISSUER, 'sub' => 'user-1', 'aud' => 'web', 'sid' => 'session-1'], TestKeys::privatePem('b'));
        $foreign = JwtForge::rs256(['alg' => 'RS256', 'kid' => 'key-1'], ['iss' => 'https://evil.example', 'sub' => 'user-1', 'aud' => 'web'], TestKeys::privatePem('a'));
        $accessToken = JwtForge::rs256(['alg' => 'RS256', 'typ' => 'at+jwt', 'kid' => 'key-1'], ['iss' => TestServer::ISSUER, 'sub' => 'user-1', 'aud' => 'web'], TestKeys::privatePem('a'));

        $logoutToken = JwtForge::rs256(['alg' => 'RS256', 'typ' => 'logout+jwt', 'kid' => 'key-1'], ['iss' => TestServer::ISSUER, 'sub' => 'user-1', 'aud' => 'web', 'sid' => 'session-1'], TestKeys::privatePem('a'));
        $untyped = JwtForge::rs256(['alg' => 'RS256', 'kid' => 'key-1'], ['iss' => TestServer::ISSUER, 'sub' => 'user-1', 'aud' => 'web', 'sid' => 'session-1'], TestKeys::privatePem('a'));

        return [
            'garbage' => ['abc'],
            'signed by another key' => [$forged],
            'issued by another server' => [$foreign],
            'an access token' => [$accessToken],
            'a logout token' => [$logoutToken],
            'a token with no type' => [$untyped],
        ];
    }

    public function testItRefusesAClientIdThatContradictsTheHint(): void
    {
        // Arrange
        $idToken = $this->t->str($this->t->signIn(), 'id_token');

        // Act
        $response = $this->endSession(['id_token_hint' => $idToken, 'client_id' => 'spa'], signedIn: true);

        // Assert
        self::assertSame(400, $response->getStatusCode());
    }

    public function testAHintWithoutASessionOnlyEndsTheBrowsersSessionForTheSamePerson(): void
    {
        // Arrange: an ID token with no sid, for user-1
        $hint = JwtForge::rs256(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'key-1'], ['iss' => TestServer::ISSUER, 'sub' => 'user-1', 'aud' => 'web'], TestKeys::privatePem('a'));

        // Act
        $this->endSession(['id_token_hint' => $hint], signedIn: true, userId: 'user-2');
        $sameUser = $this->t->terminator->terminated;
        $this->endSession(['id_token_hint' => $hint], signedIn: true, userId: 'user-1');

        // Assert
        self::assertSame([], $sameUser);
        self::assertSame(['session-1'], $this->t->terminator->terminated);
    }

    /**
     * @param array<string, string> $params
     */
    private function endSession(array $params, bool $signedIn, bool $post = false, string $sessionId = 'session-1', string $userId = 'user-1'): ResponseInterface
    {
        $request = new ServerRequest([], [], '/end-session', $post ? 'POST' : 'GET');
        $request = $post ? $request->withParsedBody($params) : $request->withQueryParams($params);
        if ($signedIn) {
            $request = $request->withAttribute(AuthorizationHandler::USER_ID, $userId)->withAttribute(AuthorizationHandler::SESSION_ID, $sessionId);
        }

        return $this->t->server->endSessionHandler()->handle($request);
    }
}
