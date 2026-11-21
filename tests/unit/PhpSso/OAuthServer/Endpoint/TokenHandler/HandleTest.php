<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Endpoint\TokenHandler;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;
use PhpSso\OAuthServer\Endpoint\TokenHandler;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Tests\Support\TestClient;
use PhpSso\OAuthServer\Tests\Support\TestServer;
use Psr\Http\Message\ResponseInterface;

#[CoversMethod(TokenHandler::class, 'handle')]
final class HandleTest extends TestCase
{
    private TestServer $t;

    protected function setUp(): void
    {
        $this->t = new TestServer();
    }

    // ------------------------------------------------------------------ authorization code

    public function testItExchangesACodeForTokens(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->exchange($code);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = $this->t->json($response);
        self::assertSame('Bearer', $body['token_type']);
        self::assertSame(3600, $body['expires_in']);
        self::assertSame('openid profile', $body['scope']);
        self::assertIsString($body['access_token']);
        self::assertIsString($body['refresh_token']);
        self::assertIsString($body['id_token']);
    }

    public function testTheAccessTokenIsASignedAtJwtForTheUserWithTheirSession(): void
    {
        // Act
        $body = $this->t->signIn();

        // Assert
        $token = $this->decode($this->t->str($body, 'access_token'));
        self::assertSame('at+jwt', $token['header']['typ']);
        $claims = $token['claims'];
        self::assertSame(TestServer::ISSUER, $claims['iss']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame([TestServer::ISSUER, 'web'], $claims['aud']);
        self::assertSame('web', $claims['client_id']);
        self::assertSame('openid profile', $claims['scope']);
        self::assertSame('session-1', $claims['sid']);
        self::assertSame('authorization_code', $claims['gty']);
        self::assertSame($this->t->clock->timestamp() + 3600, $claims['exp']);
        self::assertIsString($claims['jti']);
        self::assertIsString($claims['fid']);
    }

    public function testTheIdTokenCarriesTheNonceSessionAndAHashOfTheAccessToken(): void
    {
        // Act
        $body = $this->t->signIn();

        // Assert
        $claims = $this->decode($this->t->str($body, 'id_token'))['claims'];
        self::assertSame('web', $claims['aud']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('nonce-1', $claims['nonce']);
        self::assertSame('session-1', $claims['sid']);
        self::assertSame('Alice Example', $claims['name']);
        $expectedHash = Base64Url::encode(substr(hash('sha256', $this->t->str($body, 'access_token'), true), 0, 16));
        self::assertSame($expectedHash, $claims['at_hash']);
    }

    public function testTheIdTokenCarriesTheTimeThePersonSignedIn(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize([], authTime: 1_699_999_000));

        // Act
        $body = $this->t->json($this->exchange($code));

        // Assert
        self::assertSame(1_699_999_000, $this->decode($this->t->str($body, 'id_token'))['claims']['auth_time']);
    }

    public function testTheAuthenticationTimeSurvivesRefreshes(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize([], authTime: 1_699_999_000));
        $first = $this->t->json($this->exchange($code));

        // Act
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token')));
        $third = $this->t->json($this->refresh($this->t->str($second, 'refresh_token')));

        // Assert
        self::assertSame(1_699_999_000, $this->decode($this->t->str($second, 'id_token'))['claims']['auth_time']);
        self::assertSame(1_699_999_000, $this->decode($this->t->str($third, 'id_token'))['claims']['auth_time']);
    }

    public function testThereIsNoAuthTimeWhenTheApplicationDidNotSupplyOne(): void
    {
        // Act
        $body = $this->t->signIn();

        // Assert
        self::assertArrayNotHasKey('auth_time', $this->decode($this->t->str($body, 'id_token'))['claims']);
    }

    public function testTheIdTokenCarriesHowThePersonSignedIn(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize([], amr: ['pwd', 'otp', 'mfa']));

        // Act
        $body = $this->t->json($this->exchange($code));

        // Assert
        self::assertSame(['pwd', 'otp', 'mfa'], $this->decode($this->t->str($body, 'id_token'))['claims']['amr']);
    }

    public function testTheAuthenticationMethodsSurviveRefreshes(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize([], amr: ['pwd', 'mfa']));
        $first = $this->t->json($this->exchange($code));

        // Act
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token')));
        $third = $this->t->json($this->refresh($this->t->str($second, 'refresh_token')));

        // Assert
        self::assertSame(['pwd', 'mfa'], $this->decode($this->t->str($second, 'id_token'))['claims']['amr']);
        self::assertSame(['pwd', 'mfa'], $this->decode($this->t->str($third, 'id_token'))['claims']['amr']);
    }

    public function testThereIsNoAmrWhenTheApplicationDidNotSupplyOne(): void
    {
        // Act
        $body = $this->t->signIn();

        // Assert
        self::assertArrayNotHasKey('amr', $this->decode($this->t->str($body, 'id_token'))['claims']);
    }

    public function testTheAccessTokenDoesNotCarryTheAuthenticationMethods(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize([], amr: ['pwd']));

        // Act
        $body = $this->t->json($this->exchange($code));

        // Assert
        self::assertArrayNotHasKey('amr', $this->decode($this->t->str($body, 'access_token'))['claims']);
    }

    public function testAClaimsProviderCannotOverrideTheClaimsTheLibraryControls(): void
    {
        // Act
        $body = $this->t->signIn('openid email');

        // Assert
        $claims = $this->decode($this->t->str($body, 'id_token'))['claims'];
        self::assertSame('alice@example.com', $claims['email']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame(TestServer::ISSUER, $claims['iss']);
    }

    public function testTheAccessTokenCarriesTheClaimsThatDependOnTheClient(): void
    {
        // Arrange
        $this->t->claims->clientClaims['web'] = ['roles' => ['editor']];

        // Act
        $body = $this->t->signIn();

        // Assert
        $claims = $this->decode($this->t->str($body, 'access_token'))['claims'];
        self::assertSame(['editor'], $claims['roles']);
    }

    public function testTheIdTokenCarriesTheClaimsThatDependOnTheClient(): void
    {
        // Arrange
        $this->t->claims->clientClaims['web'] = ['roles' => ['editor']];

        // Act
        $body = $this->t->signIn();

        // Assert
        $claims = $this->decode($this->t->str($body, 'id_token'))['claims'];
        self::assertSame(['editor'], $claims['roles']);
    }

    public function testClaimsThatDependOnTheClientAreAskedForTheClientThePersonAndTheScopes(): void
    {
        // Act
        $this->t->signIn();

        // Assert
        self::assertSame([['client' => 'web', 'user' => 'user-1', 'scopes' => ['openid', 'profile']]], $this->t->claims->clientClaimRequests);
    }

    public function testClaimsThatDependOnTheClientCannotOverrideTheClaimsTheLibraryControls(): void
    {
        // Arrange
        $this->t->claims->clientClaims['web'] = ['roles' => ['editor'], 'aud' => 'https://evil.example', 'scope' => 'admin', 'sub' => 'forged'];

        // Act
        $body = $this->t->signIn();

        // Assert
        $claims = $this->decode($this->t->str($body, 'access_token'))['claims'];
        self::assertSame([TestServer::ISSUER, 'web'], $claims['aud']);
        self::assertSame('openid profile', $claims['scope']);
        self::assertSame('user-1', $claims['sub']);
        self::assertSame(['editor'], $claims['roles']);
    }

    public function testARefreshReadsTheClaimsThatDependOnTheClientAgain(): void
    {
        // Arrange
        $this->t->claims->clientClaims['web'] = ['roles' => ['editor']];
        $refreshToken = $this->t->str($this->t->signIn(), 'refresh_token');
        $this->t->claims->clientClaims['web'] = ['roles' => ['admin']];

        // Act
        $response = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $refreshToken], ['web', 's3cret']);

        // Assert
        $claims = $this->decode($this->t->str($this->t->json($response), 'access_token'))['claims'];
        self::assertSame(['admin'], $claims['roles']);
    }

    public function testThereIsNoIdTokenWithoutTheOpenidScope(): void
    {
        // Arrange
        $this->t->clients->add(new TestClient('plain', [TestServer::REDIRECT], true, [GrantType::AuthorizationCode], ['profile'], 'p'));
        $code = $this->t->codeFrom($this->t->authorize(['client_id' => 'plain', 'scope' => 'profile']));

        // Act
        $body = $this->t->json($this->t->token($this->codeForm($code), ['plain', 'p']));

        // Assert
        self::assertArrayNotHasKey('id_token', $body);
        self::assertArrayNotHasKey('refresh_token', $body); // this client may not refresh
    }

    public function testAPublicClientRedeemsACodeWithPkceAlone(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize(['client_id' => 'spa']));

        // Act
        $response = $this->t->token($this->codeForm($code) + ['client_id' => 'spa']);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testAWrongVerifierIsRefusedAndBurnsTheCode(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $wrong = $this->exchange($code, ['code_verifier' => str_repeat('x', 43)]);
        $retry = $this->exchange($code);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($wrong)['error']);
        self::assertSame('invalid_grant', $this->t->json($retry)['error']);
    }

    public function testAVerifierThatIsTooShortIsRefused(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->exchange($code, ['code_verifier' => 'short']);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testAMissingVerifierIsAnInvalidRequest(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->exchange($code, ['code_verifier' => null]);

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testAnotherRedirectUriIsRefused(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->exchange($code, ['redirect_uri' => 'https://evil.example/cb']);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testReplayingACodeRevokesWhatWasIssuedFromIt(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());
        $first = $this->t->json($this->exchange($code));
        $family = $this->decode($this->t->str($first, 'access_token'))['claims']['fid'];
        self::assertIsString($family);

        // Act
        $replay = $this->exchange($code);
        $refresh = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($first, 'refresh_token')], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($replay)['error']);
        self::assertTrue($this->t->refreshTokens->isFamilyRevoked($family));
        self::assertSame('invalid_grant', $this->t->json($refresh)['error']);
    }

    public function testACodeRequestedWithoutPkceIsRedeemedWithoutAVerifier(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);
        $code = $t->codeFrom($t->authorize(['code_challenge' => null, 'code_challenge_method' => null]));

        // Act
        $response = $t->token(['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT], ['web', 's3cret']);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        self::assertArrayHasKey('access_token', $t->json($response));
    }

    public function testAVerifierIsRefusedForACodeRequestedWithoutPkce(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);
        $code = $t->codeFrom($t->authorize(['code_challenge' => null, 'code_challenge_method' => null]));

        // Act
        $response = $t->token(['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_grant', $t->json($response)['error']);
    }

    public function testACodeRequestedWithPkceStillNeedsItsVerifierWhenPkceIsOptional(): void
    {
        // Arrange
        $t = new TestServer(requirePkceForConfidentialClients: false);
        $code = $t->codeFrom($t->authorize());

        // Act
        $response = $t->token(['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_request', $t->json($response)['error']);
    }

    public function testAnExpiredCodeIsRefused(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());
        $this->t->clock->advance(61);

        // Act
        $response = $this->exchange($code);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testACodeIssuedToAnotherClientIsRefused(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize(['client_id' => 'spa']));

        // Act
        $response = $this->exchange($code); // authenticated as "web"

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testAnUnknownCodeIsRefused(): void
    {
        // Act
        $response = $this->exchange('nope');

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testItRefusesACodeWhenThePersonLostAccessInTheMeantime(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());
        $this->t->policy->denied['web|user-1'] = true;

        // Act
        $response = $this->exchange($code);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testItRefusesACodeWhenThePersonNoLongerExists(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());
        $this->t->claims->removed['user-1'] = true;

        // Act
        $response = $this->exchange($code);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    // ------------------------------------------------------------------ refresh token

    public function testARefreshRotatesTheTokenAndKeepsTheFamilyAndSession(): void
    {
        // Arrange
        $first = $this->t->signIn();

        // Act
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token')));

        // Assert
        self::assertNotSame($first['refresh_token'], $second['refresh_token']);
        $before = $this->decode($this->t->str($first, 'access_token'))['claims'];
        $after = $this->decode($this->t->str($second, 'access_token'))['claims'];
        self::assertSame($before['fid'], $after['fid']);
        self::assertSame('session-1', $after['sid']);
        self::assertSame('refresh_token', $after['gty']);
        self::assertArrayNotHasKey('nonce', $this->decode($this->t->str($second, 'id_token'))['claims']);
    }

    public function testReusingAnOldRefreshTokenRevokesTheWholeFamily(): void
    {
        // Arrange
        $first = $this->t->signIn();
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token')));

        // Act
        $reuse = $this->refresh($this->t->str($first, 'refresh_token'));
        $current = $this->refresh($this->t->str($second, 'refresh_token'));

        // Assert
        self::assertSame('invalid_grant', $this->t->json($reuse)['error']);
        self::assertSame('invalid_grant', $this->t->json($current)['error']);
    }

    public function testARefreshMayNarrowTheScope(): void
    {
        // Arrange
        $first = $this->t->signIn();

        // Act
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token'), ['scope' => 'openid']));

        // Assert
        self::assertSame('openid', $second['scope']);
    }

    public function testARefreshCannotWidenTheScope(): void
    {
        // Arrange
        $first = $this->t->signIn();

        // Act
        $response = $this->refresh($this->t->str($first, 'refresh_token'), ['scope' => 'openid profile email']);

        // Assert
        self::assertSame('invalid_scope', $this->t->json($response)['error']);
    }

    public function testARefusedWideningOfTheScopeDoesNotSpendTheRefreshToken(): void
    {
        // Arrange
        $first = $this->t->signIn();
        $token = $this->t->str($first, 'refresh_token');
        $this->refresh($token, ['scope' => 'openid profile email admin']);

        // Act
        $retry = $this->refresh($token);

        // Assert
        self::assertArrayHasKey('access_token', $this->t->json($retry));
    }

    public function testAnExpiredRefreshTokenIsRefused(): void
    {
        // Arrange
        $first = $this->t->signIn();
        $this->t->clock->advance(2_592_001);

        // Act
        $response = $this->refresh($this->t->str($first, 'refresh_token'));

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testARefreshTokenOfAnotherClientIsRefused(): void
    {
        // Arrange
        $first = $this->t->signIn();

        // Act
        $response = $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $this->t->str($first, 'refresh_token'), 'client_id' => 'spa']);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testRevokingTheSessionStopsRefreshing(): void
    {
        // Arrange
        $first = $this->t->signIn();
        $this->t->refreshTokens->revokeSession('session-1', $this->t->clock->timestamp());

        // Act
        $response = $this->refresh($this->t->str($first, 'refresh_token'));

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testARefreshChecksAccessAgain(): void
    {
        // Arrange
        $first = $this->t->signIn();
        $this->t->policy->denied['web|user-1'] = true;

        // Act
        $response = $this->refresh($this->t->str($first, 'refresh_token'));

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    /** @param list<string> $scopes */
    private function limitWebClientTo(array $scopes): void
    {
        $this->t->clients->add(new TestClient('web', [TestServer::REDIRECT], true, [GrantType::AuthorizationCode, GrantType::RefreshToken], $scopes, 's3cret', 'https://app.example/backchannel-logout', ['https://app.example/signed-out']));
    }

    public function testARefreshDropsAScopeTheClientMayNoLongerAskFor(): void
    {
        // Arrange
        $first = $this->t->signIn('openid profile email');
        $this->limitWebClientTo(['openid', 'email']);

        // Act
        $second = $this->t->json($this->refresh($this->t->str($first, 'refresh_token')));

        // Assert
        self::assertSame('openid email', $second['scope']);
    }

    public function testARefreshWhoseScopesAreAllGoneIsRefusedWithoutSpendingTheToken(): void
    {
        // Arrange
        $first = $this->t->signIn('openid profile');
        $token = $this->t->str($first, 'refresh_token');
        $this->limitWebClientTo(['email']);

        // Act
        $refused = $this->t->json($this->refresh($token));
        $this->limitWebClientTo(['openid', 'profile', 'email']);
        $retry = $this->t->json($this->refresh($token));

        // Assert
        self::assertSame('invalid_grant', $refused['error']);
        self::assertSame('openid profile', $retry['scope']);
    }

    // ------------------------------------------------------------------ client credentials

    public function testClientCredentialsIssueAnAccessTokenForTheClientAlone(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']);

        // Assert
        self::assertSame(200, $response->getStatusCode());
        $body = $this->t->json($response);
        self::assertArrayNotHasKey('refresh_token', $body);
        self::assertArrayNotHasKey('id_token', $body);
        $claims = $this->decode($this->t->str($body, 'access_token'))['claims'];
        self::assertSame('service', $claims['sub']);
        self::assertSame('service', $claims['client_id']);
        self::assertSame('api', $claims['scope']);
        self::assertSame('client_credentials', $claims['gty']);
        self::assertArrayNotHasKey('sid', $claims);
    }

    public function testClientCredentialsAccessTokensAreForTheServerAndTheClient(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']);

        // Assert
        $claims = $this->decode($this->t->str($this->t->json($response), 'access_token'))['claims'];
        self::assertSame([TestServer::ISSUER, 'service'], $claims['aud']);
    }

    public function testClientCredentialsAccessTokensCarryNoClaimsAboutAPerson(): void
    {
        // Arrange
        $this->t->claims->clientClaims['service'] = ['roles' => ['editor']];

        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['service', 'svc-secret']);

        // Assert
        $claims = $this->decode($this->t->str($this->t->json($response), 'access_token'))['claims'];
        self::assertArrayNotHasKey('roles', $claims);
    }

    public function testClientCredentialsAcceptCredentialsInTheBodyToo(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api', 'client_id' => 'service', 'client_secret' => 'svc-secret']);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testClientCredentialsRefuseAScopeTheClientMayNotHave(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api openid'], ['service', 'svc-secret']);

        // Assert
        self::assertSame('invalid_scope', $this->t->json($response)['error']);
    }

    public function testClientCredentialsRefuseAPublicClient(): void
    {
        // Arrange
        $this->t->clients->add(new TestClient('open', [], false, [GrantType::ClientCredentials], ['api']));

        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api', 'client_id' => 'open']);

        // Assert
        self::assertSame('unauthorized_client', $this->t->json($response)['error']);
    }

    // ------------------------------------------------------------------ client authentication and request shape

    public function testAWrongSecretIsRefusedWithAChallenge(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->t->token($this->codeForm($code), ['web', 'wrong']);

        // Assert
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', $this->t->json($response)['error']);
        self::assertStringStartsWith('Basic', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testAnUnknownClientLooksTheSameAsAWrongSecret(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $unknown = $this->t->token($this->codeForm($code), ['nobody', 'x']);
        $wrong = $this->t->token($this->codeForm($code), ['web', 'x']);

        // Assert
        self::assertSame((string) $wrong->getBody(), (string) $unknown->getBody());
        self::assertSame($wrong->getStatusCode(), $unknown->getStatusCode());
    }

    public function testAConfidentialClientCannotSkipAuthentication(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->t->token($this->codeForm($code) + ['client_id' => 'web']);

        // Assert
        self::assertSame('invalid_client', $this->t->json($response)['error']);
    }

    public function testAClientMustUseOneAuthenticationMethod(): void
    {
        // Arrange
        $code = $this->t->codeFrom($this->t->authorize());

        // Act
        $response = $this->t->token($this->codeForm($code) + ['client_secret' => 's3cret'], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testItRefusesAGrantTheClientMayNotUse(): void
    {
        // Act
        $response = $this->t->token(['grant_type' => 'client_credentials', 'scope' => 'api'], ['web', 's3cret']);

        // Assert
        self::assertSame('unauthorized_client', $this->t->json($response)['error']);
    }

    #[DataProvider('unsupportedGrants')]
    public function testItRefusesGrantsItDoesNotImplement(string $grant): void
    {
        // Act
        $response = $this->t->token(['grant_type' => $grant, 'username' => 'a', 'password' => 'b'], ['web', 's3cret']);

        // Assert
        self::assertSame('unsupported_grant_type', $this->t->json($response)['error']);
    }

    /** @return array<string, array{string}> */
    public static function unsupportedGrants(): array
    {
        return ['password' => ['password'], 'implicit' => ['implicit'], 'made up' => ['magic']];
    }

    public function testItRequiresAGrantType(): void
    {
        // Act
        $response = $this->t->token([], ['web', 's3cret']);

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testItOnlyAcceptsPost(): void
    {
        // Arrange
        $request = new ServerRequest([], [], '/token', 'GET');

        // Act
        $response = $this->t->server->tokenHandler()->handle($request);

        // Assert
        self::assertSame('invalid_request', $this->t->json($response)['error']);
    }

    public function testItReadsAnUndecodedFormBody(): void
    {
        // Arrange
        $body = (new StreamFactory())->createStream(http_build_query(['grant_type' => 'client_credentials', 'scope' => 'api', 'client_id' => 'service', 'client_secret' => 'svc-secret']));
        $request = (new ServerRequest([], [], '/token', 'POST'))->withBody($body);

        // Act
        $response = $this->t->server->tokenHandler()->handle($request);

        // Assert
        self::assertSame(200, $response->getStatusCode());
    }

    public function testErrorResponsesAreNeverCached(): void
    {
        // Act
        $response = $this->exchange('nope');

        // Assert
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('no-cache', $response->getHeaderLine('Pragma'));
    }

    // ------------------------------------------------------------------ device code

    public function testAPendingDeviceIsToldToKeepPolling(): void
    {
        // Arrange
        [$deviceCode] = $this->startDevice();

        // Act
        $response = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame('authorization_pending', $this->t->json($response)['error']);
    }

    public function testADevicePollingTooFastIsToldToSlowDownAndTheIntervalGrows(): void
    {
        // Arrange
        [$deviceCode] = $this->startDevice();
        $this->pollDevice($deviceCode);

        // Act
        $tooFast = $this->pollDevice($deviceCode); // interval becomes 10
        $this->t->clock->advance(6);
        $stillTooSoon = $this->pollDevice($deviceCode); // 6 < 10, so it becomes 15
        $this->t->clock->advance(16);
        $patient = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame('slow_down', $this->t->json($tooFast)['error']);
        self::assertSame('slow_down', $this->t->json($stillTooSoon)['error']);
        self::assertSame('authorization_pending', $this->t->json($patient)['error']);
    }

    public function testAnApprovedDeviceGetsTokensOnce(): void
    {
        // Arrange
        [$deviceCode, $userCode] = $this->startDevice();
        $this->t->server->deviceVerifier()->approve($userCode, 'user-1', 'session-9');
        $this->t->clock->advance(6);

        // Act
        $first = $this->pollDevice($deviceCode);
        $this->t->clock->advance(6);
        $second = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame(200, $first->getStatusCode());
        $body = $this->t->json($first);
        $claims = $this->decode($this->t->str($body, 'access_token'))['claims'];
        self::assertSame('user-1', $claims['sub']);
        self::assertSame('session-9', $claims['sid']);
        self::assertSame('urn:ietf:params:oauth:grant-type:device_code', $claims['gty']);
        self::assertArrayHasKey('refresh_token', $body);
        self::assertSame('invalid_grant', $this->t->json($second)['error']);
    }

    public function testADeniedDeviceIsToldSoAndNeverGetsTokens(): void
    {
        // Arrange
        [$deviceCode, $userCode] = $this->startDevice();
        $this->t->server->deviceVerifier()->deny($userCode);
        $this->t->clock->advance(6);

        // Act
        $response = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame('access_denied', $this->t->json($response)['error']);
    }

    public function testAnExpiredDeviceCodeIsReported(): void
    {
        // Arrange
        [$deviceCode] = $this->startDevice();
        $this->t->clock->advance(601);

        // Act
        $response = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame('expired_token', $this->t->json($response)['error']);
    }

    public function testAnotherClientCannotUseTheDeviceCode(): void
    {
        // Arrange
        [$deviceCode] = $this->startDevice();
        $this->t->clients->add(new TestClient('tv2', [], false, [GrantType::DeviceCode], ['openid']));

        // Act
        $response = $this->t->token(['grant_type' => GrantType::DeviceCode->value, 'device_code' => $deviceCode, 'client_id' => 'tv2']);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    public function testADeviceApprovalIsCheckedAgainstThePolicyAgainWhenTokensAreIssued(): void
    {
        // Arrange
        [$deviceCode, $userCode] = $this->startDevice();
        $this->t->server->deviceVerifier()->approve($userCode, 'user-1', null);
        $this->t->policy->denied['tv|user-1'] = true;
        $this->t->clock->advance(6);

        // Act
        $response = $this->pollDevice($deviceCode);

        // Assert
        self::assertSame('invalid_grant', $this->t->json($response)['error']);
    }

    // ------------------------------------------------------------------ helpers

    /**
     * @param array<string, string|null> $overrides
     */
    private function exchange(string $code, array $overrides = []): ResponseInterface
    {
        $form = array_filter($overrides + $this->codeForm($code), static fn (?string $v): bool => $v !== null);

        return $this->t->token($form, ['web', 's3cret']);
    }

    /** @return array<string, string> */
    private function codeForm(string $code): array
    {
        return ['grant_type' => 'authorization_code', 'code' => $code, 'redirect_uri' => TestServer::REDIRECT, 'code_verifier' => TestServer::VERIFIER];
    }

    /** @param array<string, string> $extra */
    private function refresh(string $token, array $extra = []): ResponseInterface
    {
        return $this->t->token(['grant_type' => 'refresh_token', 'refresh_token' => $token] + $extra, ['web', 's3cret']);
    }

    /** @return array{string, string} device code and the user code as the person types it */
    private function startDevice(): array
    {
        $request = (new ServerRequest([], [], '/device_authorization', 'POST'))->withParsedBody(['client_id' => 'tv', 'scope' => 'openid profile']);
        $body = $this->t->json($this->t->server->deviceAuthorizationHandler()->handle($request));
        self::assertIsString($body['device_code']);
        self::assertIsString($body['user_code']);

        return [$body['device_code'], $body['user_code']];
    }

    private function pollDevice(string $deviceCode): ResponseInterface
    {
        return $this->t->token(['grant_type' => GrantType::DeviceCode->value, 'device_code' => $deviceCode, 'client_id' => 'tv']);
    }

    /** @return array{header: array<string, mixed>, claims: array<string, mixed>} */
    private function decode(string $jwt): array
    {
        return (new JwtDecoder($this->t->keys))->decode($jwt);
    }
}
