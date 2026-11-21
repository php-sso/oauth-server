<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\ClaimsValidator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Jwt\ClaimsValidator;
use PhpSso\OAuthServer\Jwt\InvalidJwt;
use PhpSso\OAuthServer\Tests\Support\FrozenClock;

#[CoversMethod(ClaimsValidator::class, 'validate')]
final class ValidateTest extends TestCase
{
    private const NOW = 1_700_000_000;

    private FrozenClock $clock;
    private ClaimsValidator $validator;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock(self::NOW);
        $this->validator = new ClaimsValidator($this->clock, 'https://sso.example.com', 30);
    }

    public function testItAcceptsClaimsThatAreCurrentAndForUs(): void
    {
        // Arrange
        $claims = ['iss' => 'https://sso.example.com', 'aud' => 'client-1', 'exp' => self::NOW + 60, 'iat' => self::NOW - 5, 'nbf' => self::NOW - 5];

        // Act
        $this->validator->validate($claims, 'client-1');

        // Assert
        $this->addToAssertionCount(1); // no exception
    }

    public function testItAcceptsAnAudienceThatIsOneOfSeveral(): void
    {
        // Arrange
        $claims = ['iss' => 'https://sso.example.com', 'aud' => ['api', 'client-1'], 'exp' => self::NOW + 60];

        // Act
        $this->validator->validate($claims, 'client-1');

        // Assert
        $this->addToAssertionCount(1);
    }

    public function testItSkipsTheAudienceCheckWhenNoneIsRequested(): void
    {
        // Arrange
        $claims = ['iss' => 'https://sso.example.com', 'exp' => self::NOW + 60];

        // Act
        $this->validator->validate($claims);

        // Assert
        $this->addToAssertionCount(1);
    }

    /** @param array<string, mixed> $claims */
    #[DataProvider('unacceptableClaims')]
    public function testItRejectsClaimsThatAreWrong(array $claims, ?string $audience): void
    {
        // Arrange
        $this->expectException(InvalidJwt::class);

        // Act
        $this->validator->validate($claims, $audience);
    }

    /** @return array<string, array{array<string, mixed>, string|null}> */
    public static function unacceptableClaims(): array
    {
        $now = self::NOW;
        $ok = ['iss' => 'https://sso.example.com', 'exp' => $now + 60];

        return [
            'another issuer' => [['iss' => 'https://evil.example', 'exp' => $now + 60], null],
            'no issuer' => [['exp' => $now + 60], null],
            'no expiry' => [['iss' => 'https://sso.example.com'], null],
            'expiry as text' => [['iss' => 'https://sso.example.com', 'exp' => (string) ($now + 60)], null],
            'expired beyond the leeway' => [['iss' => 'https://sso.example.com', 'exp' => $now - 30], null],
            'not valid yet' => [$ok + ['nbf' => $now + 31], null],
            'issued in the future' => [$ok + ['iat' => $now + 31], null],
            'other audience' => [$ok + ['aud' => 'client-2'], 'client-1'],
            'no audience when one is required' => [$ok, 'client-1'],
            'audience list without us' => [$ok + ['aud' => ['api', 'client-2']], 'client-1'],
        ];
    }

    public function testItToleratesSmallClockDifferencesAtTheEdgeOfTheLeeway(): void
    {
        // Arrange
        $expiredJustNow = ['iss' => 'https://sso.example.com', 'exp' => self::NOW - 29];

        // Act
        $this->validator->validate($expiredJustNow);

        // Assert
        $this->addToAssertionCount(1);
    }
}
