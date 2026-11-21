<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\VerificationKeySet;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Jwt\VerificationKey;
use PhpSso\OAuthServer\Jwt\VerificationKeySet;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(VerificationKeySet::class, 'fromJwks')]
#[CoversMethod(VerificationKeySet::class, 'verificationKeys')]
final class FromJwksTest extends TestCase
{
    /** @return array<string, mixed> */
    private function jwk(string $kid, string $name = 'a'): array
    {
        return TestKeys::signingKey($kid, $name)->verificationKey()->toJwk();
    }

    /** @return list<string> */
    private function kids(VerificationKeySet $set): array
    {
        return array_map(static fn (VerificationKey $key): string => $key->kid, $set->verificationKeys());
    }

    public function testItReadsTheRsaSigningKeysOfAProvider(): void
    {
        // Arrange
        $document = ['keys' => [$this->jwk('one', 'a'), $this->jwk('two', 'b')]];

        // Act
        $set = VerificationKeySet::fromJwks($document);

        // Assert
        self::assertSame(['one', 'two'], $this->kids($set));
    }

    public function testItLeavesOutKeysItCannotUseInsteadOfFailing(): void
    {
        // Arrange
        $document = ['keys' => [
            ['kty' => 'EC', 'kid' => 'ec', 'crv' => 'P-256', 'x' => 'AAAA', 'y' => 'AAAA'],
            ['use' => 'enc'] + $this->jwk('encryption'),
            ['alg' => 'RS512'] + $this->jwk('other-algorithm'),
            ['kty' => 'RSA', 'kid' => 'broken', 'n' => '!!', 'e' => 'AQAB'],
            ['kty' => 'RSA', 'n' => 'AQAB', 'e' => 'AQAB'],
            'not an object',
            [],
            $this->jwk('good'),
        ]];

        // Act
        $set = VerificationKeySet::fromJwks($document);

        // Assert
        self::assertSame(['good'], $this->kids($set));
    }

    public function testAKeyBelowTwoThousandAndFortyEightBitsIsLeftOut(): void
    {
        // Arrange
        $small = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($small);
        $details = openssl_pkey_get_details($small);
        self::assertIsArray($details);
        $rsa = $details['rsa'] ?? null;
        self::assertIsArray($rsa);
        self::assertIsString($rsa['n'] ?? null);
        self::assertIsString($rsa['e'] ?? null);
        $document = ['keys' => [
            ['kty' => 'RSA', 'kid' => 'small', 'n' => Base64Url::encode($rsa['n']), 'e' => Base64Url::encode($rsa['e'])],
            $this->jwk('good'),
        ]];

        // Act
        $set = VerificationKeySet::fromJwks($document);

        // Assert
        self::assertSame(['good'], $this->kids($set));
    }

    public function testSomethingThatIsNotAKeySetGivesAnEmptySet(): void
    {
        // Arrange
        $documents = [[], ['keys' => 'nope'], ['keys' => null], ['other' => 1]];

        // Act
        $counts = array_map(static fn (array $document): int => count(VerificationKeySet::fromJwks($document)->verificationKeys()), $documents);

        // Assert
        self::assertSame([0, 0, 0, 0], $counts);
    }

    public function testADecoderBuiltOnTheSetVerifiesATokenTheProviderSigned(): void
    {
        // Arrange
        $signing = TestKeys::signingKey('provider-key');
        $jwt = (new JwtEncoder(new StaticKeyProvider($signing)))->encode(['sub' => 'user-1']);
        $decoder = new JwtDecoder(VerificationKeySet::fromJwks(['keys' => [$this->jwk('provider-key')]]));

        // Act
        $decoded = $decoder->decode($jwt);

        // Assert
        self::assertSame('user-1', $decoded['claims']['sub']);
    }
}
