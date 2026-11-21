<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\JwtDecoder;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;
use PhpSso\OAuthServer\Jwt\InvalidJwt;
use PhpSso\OAuthServer\Jwt\JwtDecoder;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use PhpSso\OAuthServer\Jwt\SigningKey;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\JwtForge;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(JwtDecoder::class, 'decode')]
final class DecodeTest extends TestCase
{
    private SigningKey $signingKey;
    private JwtDecoder $decoder;

    protected function setUp(): void
    {
        $this->signingKey = TestKeys::signingKey('key-1');
        $this->decoder = new JwtDecoder(new StaticKeyProvider($this->signingKey));
    }

    public function testItReturnsTheHeaderAndClaimsOfAGenuineToken(): void
    {
        // Arrange
        $jwt = (new JwtEncoder(new StaticKeyProvider($this->signingKey)))->encode(['sub' => 'user-1', 'exp' => 123]);

        // Act
        $decoded = $this->decoder->decode($jwt);

        // Assert
        self::assertSame(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'key-1'], $decoded['header']);
        self::assertSame(['sub' => 'user-1', 'exp' => 123], $decoded['claims']);
    }

    public function testItAcceptsATokenSignedByAnIndependentLibrary(): void
    {
        // Arrange
        $config = Configuration::forAsymmetricSigner(new Sha256(), InMemory::plainText($this->signingKey->privateKeyPem), InMemory::plainText($this->signingKey->verificationKey()->publicKeyPem));
        $jwt = $config->builder()->relatedTo('user-1')->withHeader('kid', 'key-1')->getToken($config->signer(), $config->signingKey())->toString();

        // Act
        $decoded = $this->decoder->decode($jwt);

        // Assert
        self::assertSame('user-1', $decoded['claims']['sub']);
    }

    public function testItAcceptsATokenSignedByARetiredKeyThatIsStillPublished(): void
    {
        // Arrange
        $retiredKey = TestKeys::signingKey('old', 'b');
        $jwt = (new JwtEncoder(new StaticKeyProvider($retiredKey)))->encode(['sub' => 'user-1']);
        $decoder = new JwtDecoder(new StaticKeyProvider($this->signingKey, [$retiredKey->verificationKey()]));

        // Act
        $decoded = $decoder->decode($jwt);

        // Assert
        self::assertSame('user-1', $decoded['claims']['sub']);
    }

    public function testItRejectsATokenWhoseClaimsWereChanged(): void
    {
        // Arrange
        $jwt = (new JwtEncoder(new StaticKeyProvider($this->signingKey)))->encode(['sub' => 'user-1']);
        [$header, , $signature] = explode('.', $jwt);
        $forged = $header . '.' . Base64Url::encode('{"sub":"admin"}') . '.' . $signature;
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($forged);
    }

    public function testItRejectsATokenSignedByAnotherKeyUnderTheSameKid(): void
    {
        // Arrange
        $impostor = JwtForge::rs256(['alg' => 'RS256', 'kid' => 'key-1'], ['sub' => 'admin'], TestKeys::privatePem('b'));
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($impostor);
    }

    public function testItRejectsATokenWithNoSignatureAtAll(): void
    {
        // Arrange
        $jwt = JwtForge::unsigned(['alg' => 'none', 'kid' => 'key-1'], ['sub' => 'admin']);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    public function testItRejectsAlgNoneEvenWithASignaturePresent(): void
    {
        // Arrange
        $jwt = JwtForge::unsigned(['alg' => 'none', 'kid' => 'key-1'], ['sub' => 'admin'], 'c2lnbmF0dXJl');
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    public function testItRejectsAnHmacTokenSignedWithThePublicKeyAsSecret(): void
    {
        // Arrange: the classic algorithm confusion attack
        $publicPem = $this->signingKey->verificationKey()->publicKeyPem;
        $jwt = JwtForge::hs256(['alg' => 'HS256', 'kid' => 'key-1'], ['sub' => 'admin'], $publicPem);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    public function testItRejectsAnAlgorithmOtherThanRs256EvenWhenTheSignatureIsGenuine(): void
    {
        // Arrange
        $jwt = JwtForge::rs256(['alg' => 'RS512', 'kid' => 'key-1'], ['sub' => 'user-1'], $this->signingKey->privateKeyPem);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    public function testItRejectsATokenSignedWithAnUnknownKid(): void
    {
        // Arrange
        $jwt = JwtForge::rs256(['alg' => 'RS256', 'kid' => 'other'], ['sub' => 'user-1'], $this->signingKey->privateKeyPem);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    public function testItRejectsATokenThatDoesNotNameItsKey(): void
    {
        // Arrange: with a single known key it would be tempting to try it anyway; we do not
        $jwt = JwtForge::rs256(['alg' => 'RS256'], ['sub' => 'user-1'], $this->signingKey->privateKeyPem);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    /** @param array<string, mixed> $extraHeader */
    #[DataProvider('headersThatPointElsewhere')]
    public function testItRejectsHeadersThatPointAtOtherKeysOrNeedExtensions(array $extraHeader): void
    {
        // Arrange
        $header = ['alg' => 'RS256', 'kid' => 'key-1'] + $extraHeader;
        $jwt = JwtForge::rs256($header, ['sub' => 'user-1'], $this->signingKey->privateKeyPem);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function headersThatPointElsewhere(): array
    {
        return [
            'jku' => [['jku' => 'https://evil.example/keys']],
            'jwk' => [['jwk' => ['kty' => 'RSA']]],
            'x5u' => [['x5u' => 'https://evil.example/cert']],
            'x5c' => [['x5c' => ['MIIB']]],
            'crit' => [['crit' => ['exp']]],
        ];
    }

    #[DataProvider('malformedTokens')]
    public function testItRejectsMalformedTokens(string $jwt): void
    {
        // Arrange
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($jwt);
    }

    /** @return array<string, array{string}> */
    public static function malformedTokens(): array
    {
        return [
            'empty' => [''],
            'one part' => ['abc'],
            'two parts' => ['abc.def'],
            'four parts' => ['a.b.c.d'],
            'header is not base64url' => ['!!!.e30.e30'],
            'header is not json' => [Base64Url::encode('nope') . '.e30.e30'],
            'header is a list' => [Base64Url::encode('[1]') . '.e30.e30'],
        ];
    }

    public function testItRejectsEveryTokenThatDiffersFromAGenuineOneByOneCharacter(): void
    {
        // Arrange
        $jwt = (new JwtEncoder(new StaticKeyProvider($this->signingKey)))->encode(['sub' => 'user-1', 'exp' => 123]);
        $accepted = [];

        // Act
        for ($i = 0; $i < strlen($jwt); ++$i) {
            $mutated = $jwt;
            $mutated[$i] = $jwt[$i] === 'A' ? 'B' : 'A';
            try {
                $this->decoder->decode($mutated);
                $accepted[] = $i;
            } catch (InvalidJwt) {
                // expected
            }
        }

        // Assert
        self::assertSame([], $accepted);
    }

    public function testItRejectsASignatureSpelledInANonCanonicalWay(): void
    {
        // Arrange
        $jwt = (new JwtEncoder(new StaticKeyProvider($this->signingKey)))->encode(['sub' => 'user-1', 'exp' => 123]);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        $last = strlen($jwt) - 1;
        $value = strpos($alphabet, $jwt[$last]);
        self::assertNotFalse($value);
        $respelled = substr($jwt, 0, $last) . $alphabet[($value ^ 1)]; // a 2048-bit signature ends in 4 unused bits; flip one
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($respelled);
    }

    public function testItRejectsAPayloadThatIsNotAJsonObject(): void
    {
        // Arrange
        $input = Base64Url::encode('{"alg":"RS256","kid":"key-1"}') . '.' . Base64Url::encode('[1,2]');
        $key = openssl_pkey_get_private($this->signingKey->privateKeyPem);
        self::assertNotFalse($key);
        openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);
        self::assertIsString($signature);
        $this->expectException(InvalidJwt::class);

        // Act
        $this->decoder->decode($input . '.' . Base64Url::encode($signature));
    }
}
