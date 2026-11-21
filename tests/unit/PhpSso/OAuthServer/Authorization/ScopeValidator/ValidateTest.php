<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Authorization\ScopeValidator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Tests\Support\TestServer;

#[CoversMethod(ScopeValidator::class, 'validate')]
final class ValidateTest extends TestCase
{
    private ScopeValidator $validator;
    private Client $client;

    protected function setUp(): void
    {
        $t = new TestServer();
        $this->validator = new ScopeValidator($t->config);
        $client = $t->clients->find('web');
        self::assertNotNull($client);
        $this->client = $client;
    }

    public function testItReturnsTheRequestedScopesOnce(): void
    {
        // Act
        $scopes = $this->validator->validate($this->client, 'openid  profile openid');

        // Assert
        self::assertSame(['openid', 'profile'], $scopes);
    }

    #[DataProvider('refused')]
    public function testItRefusesWhatIsEmptyUnknownOrNotAllowedToTheClient(?string $requested): void
    {
        // Arrange
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('invalid_scope');

        // Act
        $this->validator->validate($this->client, $requested);
    }

    /** @return array<string, array{string|null}> */
    public static function refused(): array
    {
        return [
            'nothing' => [null],
            'only spaces' => ['  '],
            'unknown to the server' => ['openid admin'],
            'known to the server but not to this client' => ['openid api'],
        ];
    }
}
