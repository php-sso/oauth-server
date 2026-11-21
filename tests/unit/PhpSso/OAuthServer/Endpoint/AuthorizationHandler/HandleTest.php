<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\AuthorizationHandler;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Endpoint\AuthorizationHandler;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Pkce\Pkce;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use PhpSso\OAuthServer\Token\TokenHash;

#[CoversMethod(AuthorizationHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    public function testItRedirectsBackWithACodeStateAndIssuer(): void
    {
        // Act
        $response = $this->t->authorize();

        // Assert
        self::assertSame(302, $response->getStatusCode());
        self::assertStringStartsWith(TestServer::REDIRECT . '?', $response->getHeaderLine('Location'));
        $query = $this->t->query($response);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $query['code']);
        self::assertSame('state-1', $query['state']);
        self::assertSame(TestServer::ISSUER, $query['iss']);
    }

    public function testItStoresOnlyTheHashOfTheCodeWithEverythingNeededToRedeemIt(): void
    {
        // Act
        $code = $this->t->codeFrom($this->t->authorize());

        // Assert
        $record = $this->t->codes->find(TokenHash::of($code));
        self::assertNotNull($record);
        self::assertNull($this->t->codes->find($code));
        self::assertSame('web', $record->clientId);
        self::assertSame('user-1', $record->userId);
        self::assertSame(['openid', 'profile'], $record->scopes);
        self::assertSame('nonce-1', $record->nonce);
        self::assertSame('session-1', $record->sessionId);
        self::assertSame($this->t->clock->timestamp() + 60, $record->expiresAt);
    }

    public function testItKeepsAQueryStringAlreadyPresentInTheRedirectUri(): void
    {
        // Arrange
        $this->t->clients->add(new TestClient('with-query', ['https://app.example/cb?tenant=a'], false, [GrantType::AuthorizationCode], ['openid']));

        // Act
        $response = $this->t->authorize(['client_id' => 'with-query', 'redirect_uri' => 'https://app.example/cb?tenant=a', 'scope' => 'openid']);

        // Assert
        $query = $this->t->query($response);
        self::assertSame('a', $query['tenant']);
        self::assertArrayHasKey('code', $query);
    }

    public function testItAsksForLoginWhenNobodyIsSignedIn(): void
    {
        // Act
        $response = $this->t->authorize([], userId: null);

        // Assert
        self::assertSame('login page', (string) $response->getBody());
    }

    public function testItAnswersLoginRequiredToTheClientForPromptNone(): void
    {
        // Act
        $response = $this->t->authorize(['prompt' => 'none'], userId: null);

        // Assert
        self::assertStringStartsWith(TestServer::REDIRECT, $response->getHeaderLine('Location'));
        self::assertSame('login_required', $this->t->query($response)['error']);
        self::assertSame('state-1', $this->t->query($response)['state']);
    }

    public function testItShowsTheAccessDeniedScreenWhenThePolicySaysNo(): void
    {
        // Arrange
        $this->t->policy->denied['web|user-1'] = true;

        // Act
        $response = $this->t->authorize();

        // Assert
        self::assertSame(403, $response->getStatusCode());
        self::assertSame('no access to web', (string) $response->getBody());
        self::assertNull($this->t->codes->find(''));
    }

    #[DataProvider('errorsThatMustNotBeRedirected')]
    public function testItNeverRedirectsErrorsAboutTheClientOrRedirectUri(string $param, ?string $value): void
    {
        // Act
        $response = $this->t->authorize([$param => $value]);

        // Assert
        self::assertSame(400, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Location'));
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    /** @return array<string, array{string, string|null}> */
    public static function errorsThatMustNotBeRedirected(): array
    {
        return [
            'unknown client' => ['client_id', 'nobody'],
            'missing client' => ['client_id', null],
            'redirect uri of someone else' => ['redirect_uri', 'https://evil.example/cb'],
            'redirect uri differing in a trailing slash' => ['redirect_uri', TestServer::REDIRECT . '/'],
            'redirect uri differing in case' => ['redirect_uri', 'https://APP.example/cb'],
            'missing redirect uri' => ['redirect_uri', null],
        ];
    }

    #[DataProvider('errorsThatAreRedirected')]
    public function testItRedirectsOtherErrorsToTheClientWithTheState(string $param, ?string $value, string $expectedError): void
    {
        // Act
        $response = $this->t->authorize([$param => $value]);

        // Assert
        self::assertSame(302, $response->getStatusCode());
        $query = $this->t->query($response);
        self::assertSame($expectedError, $query['error']);
        self::assertSame('state-1', $query['state']);
        self::assertArrayNotHasKey('code', $query);
    }

    /** @return array<string, array{string, string|null, string}> */
    public static function errorsThatAreRedirected(): array
    {
        return [
            'implicit flow' => ['response_type', 'token', 'unsupported_response_type'],
            'no response type' => ['response_type', null, 'invalid_request'],
            'no code challenge' => ['code_challenge', null, 'invalid_request'],
            'malformed code challenge' => ['code_challenge', 'short', 'invalid_request'],
            'plain method' => ['code_challenge_method', 'plain', 'invalid_request'],
            'no method' => ['code_challenge_method', null, 'invalid_request'],
            'request object' => ['request', 'eyJhbGciOiJub25lIn0.e30.', 'request_not_supported'],
            'request uri' => ['request_uri', 'https://app.example/request.jwt', 'request_uri_not_supported'],
            'unknown scope' => ['scope', 'openid admin', 'invalid_scope'],
            'scope the client may not ask for' => ['scope', 'openid api', 'invalid_scope'],
            'no scope' => ['scope', null, 'invalid_scope'],
            'unsupported prompt' => ['prompt', 'consent', 'invalid_request'],
            'prompt none combined with login' => ['prompt', 'none login', 'invalid_request'],
            'max_age that is not a number' => ['max_age', 'soon', 'invalid_request'],
            'negative max_age' => ['max_age', '-5', 'invalid_request'],
        ];
    }

    public function testAConfidentialClientMayLeavePkceOutWhenTheServerAllowsIt(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);

        // Act
        $response = $t->authorize(['code_challenge' => null, 'code_challenge_method' => null]);

        // Assert
        self::assertSame(302, $response->getStatusCode());
        self::assertArrayHasKey('code', $t->query($response));
    }

    public function testACodeRequestedWithoutPkceIsStoredWithNoChallenge(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);

        // Act
        $code = $t->codeFrom($t->authorize(['code_challenge' => null, 'code_challenge_method' => null]));

        // Assert
        self::assertSame(Pkce::NONE, $t->codes->find(TokenHash::of($code))?->codeChallenge);
    }

    public function testAPublicClientStillNeedsPkceWhenTheServerAllowsConfidentialClientsToSkipIt(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);

        // Act
        $response = $t->authorize(['client_id' => 'spa', 'code_challenge' => null, 'code_challenge_method' => null]);

        // Assert
        self::assertSame('invalid_request', $t->query($response)['error']);
    }

    public function testAChallengeFromAConfidentialClientIsStillCheckedWhenPkceIsOptional(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);

        // Act
        $response = $t->authorize(['code_challenge' => 'short']);

        // Assert
        self::assertSame('invalid_request', $t->query($response)['error']);
    }

    public function testAMethodWithoutAChallengeIsRefusedWhenPkceIsOptional(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);

        // Act
        $response = $t->authorize(['code_challenge' => null]);

        // Assert
        self::assertSame('invalid_request', $t->query($response)['error']);
    }

    public function testAConfidentialClientCannotLeavePkceOutByDefault(): void
    {
        // Arrange
        $t = new TestServer();

        // Act
        $response = $t->authorize(['code_challenge' => null, 'code_challenge_method' => null]);

        // Assert
        self::assertSame('invalid_request', $t->query($response)['error']);
    }

    public function testItRefusesAClientThatMayNotUseTheCodeFlow(): void
    {
        // Act
        $response = $this->t->authorize(['client_id' => 'service', 'redirect_uri' => 'https://x/cb']);

        // Assert: "service" has no redirect URIs, so this is refused before any redirect
        self::assertSame(400, $response->getStatusCode());
    }

    public function testPromptLoginForcesAnotherLoginEvenWhenSignedIn(): void
    {
        // Act
        $response = $this->t->authorize(['prompt' => 'login'], authTime: $this->t->clock->timestamp());

        // Assert
        self::assertSame('login page', (string) $response->getBody());
        $login = $this->t->authorizationUi->loginRequest;
        self::assertNotNull($login);
        self::assertTrue($login->getAttribute(AuthorizationHandler::FORCE_LOGIN));
    }

    public function testTheLoginScreenGetsTheRequestToResumeWithoutPromptOrMaxAge(): void
    {
        // Act
        $this->t->authorize(['prompt' => 'login', 'max_age' => '60'], authTime: $this->t->clock->timestamp());

        // Assert
        $resume = $this->t->authorizationUi->loginRequest?->getAttribute(AuthorizationHandler::RESUME_PARAMS);
        self::assertIsArray($resume);
        self::assertSame('web', $resume['client_id']);
        self::assertSame('state-1', $resume['state']);
        self::assertArrayNotHasKey('prompt', $resume);
        self::assertArrayNotHasKey('max_age', $resume);
    }

    public function testResumingWithoutPromptLoginIssuesTheCode(): void
    {
        // Act: the second request, after the forced login, as the resume parameters describe it
        $response = $this->t->authorize(['prompt' => null], authTime: $this->t->clock->timestamp());

        // Assert
        self::assertArrayHasKey('code', $this->t->query($response));
    }

    public function testAnOrdinaryLoginIsNotForced(): void
    {
        // Act
        $this->t->authorize([], userId: null);

        // Assert
        $login = $this->t->authorizationUi->loginRequest;
        self::assertNotNull($login);
        self::assertNull($login->getAttribute(AuthorizationHandler::FORCE_LOGIN));
    }

    public function testMaxAgeForcesALoginWhenTheLastAuthenticationIsTooOld(): void
    {
        // Arrange
        $signedInAt = $this->t->clock->timestamp();
        $this->t->clock->advance(301);

        // Act
        $response = $this->t->authorize(['max_age' => '300'], authTime: $signedInAt);

        // Assert
        self::assertSame('login page', (string) $response->getBody());
        self::assertTrue($this->t->authorizationUi->loginRequest?->getAttribute(AuthorizationHandler::FORCE_LOGIN));
    }

    public function testMaxAgeIsSatisfiedByARecentEnoughAuthentication(): void
    {
        // Arrange
        $signedInAt = $this->t->clock->timestamp();
        $this->t->clock->advance(300);

        // Act
        $response = $this->t->authorize(['max_age' => '300'], authTime: $signedInAt);

        // Assert
        self::assertArrayHasKey('code', $this->t->query($response));
    }

    public function testMaxAgeForcesALoginWhenTheAuthenticationTimeIsUnknown(): void
    {
        // Act
        $response = $this->t->authorize(['max_age' => '300']);

        // Assert
        self::assertSame('login page', (string) $response->getBody());
    }

    public function testMaxAgeZeroAlwaysForcesALoginButResumingDoesNotLoopForever(): void
    {
        // Arrange
        $signedInAt = $this->t->clock->timestamp();
        $this->t->clock->advance(2);

        // Act
        $forced = $this->t->authorize(['max_age' => '0'], authTime: $signedInAt);
        $resumed = $this->t->authorize(['max_age' => null], authTime: $signedInAt);

        // Assert
        self::assertSame('login page', (string) $forced->getBody());
        self::assertArrayHasKey('code', $this->t->query($resumed));
    }

    public function testPromptNoneAnswersLoginRequiredWhenReauthenticationWouldBeNeeded(): void
    {
        // Act
        $response = $this->t->authorize(['prompt' => 'none', 'max_age' => '10'], authTime: $this->t->clock->timestamp() - 100);

        // Assert
        self::assertSame('login_required', $this->t->query($response)['error']);
    }

    public function testPromptNoneStillIssuesACodeForARecentEnoughSession(): void
    {
        // Act
        $response = $this->t->authorize(['prompt' => 'none', 'max_age' => '10'], authTime: $this->t->clock->timestamp());

        // Assert
        self::assertArrayHasKey('code', $this->t->query($response));
    }

    public function testItStoresTheAuthenticationTimeWithTheCode(): void
    {
        // Act
        $code = $this->t->codeFrom($this->t->authorize([], authTime: 1_699_999_000));

        // Assert
        self::assertSame(1_699_999_000, $this->t->codes->find(TokenHash::of($code))?->authTime);
    }

    public function testItStoresTheAuthenticationMethodsWithTheCode(): void
    {
        // Act
        $code = $this->t->codeFrom($this->t->authorize([], amr: ['pwd', 'otp', 'mfa']));

        // Assert
        self::assertSame(['pwd', 'otp', 'mfa'], $this->t->codes->find(TokenHash::of($code))?->amr);
    }

    public function testItKeepsOnlyMethodNamesThatCanBeTrusted(): void
    {
        // Act
        $code = $this->t->codeFrom($this->t->authorize([], amr: ['pwd', '', 'two words', 5, 'pwd', ['x'], 'mfa', str_repeat('a', 65)]));

        // Assert
        self::assertSame(['pwd', 'mfa'], $this->t->codes->find(TokenHash::of($code))?->amr);
    }

    public function testItIgnoresMethodsThatAreNotAListOrHaveNothingUsable(): void
    {
        // Act
        $text = $this->t->codeFrom($this->t->authorize([], amr: 'pwd'));
        $empty = $this->t->codeFrom($this->t->authorize([], amr: []));
        $junk = $this->t->codeFrom($this->t->authorize([], amr: ['', ' ']));

        // Assert
        self::assertNull($this->t->codes->find(TokenHash::of($text))?->amr);
        self::assertNull($this->t->codes->find(TokenHash::of($empty))?->amr);
        self::assertNull($this->t->codes->find(TokenHash::of($junk))?->amr);
    }

    public function testItRegistersTheClientForTheSessionSoLogoutCanReachIt(): void
    {
        // Act
        $this->t->authorize([], sessionId: 'session-7');

        // Assert
        self::assertSame(['web'], $this->t->sessions->clientsOf('session-7'));
    }

    public function testItDoesNotRegisterAnythingWhenNobodyIsSignedIn(): void
    {
        // Act
        $this->t->authorize([], userId: null, sessionId: null);

        // Assert
        self::assertSame([], $this->t->sessions->clientsOf('session-7'));
    }

    public function testItAcceptsAPostedRequestToo(): void
    {
        // Arrange
        $request = (new ServerRequest([], [], '/authorize', 'POST'))
            ->withParsedBody([
                'response_type' => 'code', 'client_id' => 'web', 'redirect_uri' => TestServer::REDIRECT, 'scope' => 'openid',
                'code_challenge' => Pkce::challengeFor(TestServer::VERIFIER), 'code_challenge_method' => 'S256',
            ])
            ->withAttribute(AuthorizationHandler::USER_ID, 'user-1');

        // Act
        $response = $this->t->server->authorizationHandler()->handle($request);

        // Assert
        self::assertArrayHasKey('code', $this->t->query($response));
    }
}
