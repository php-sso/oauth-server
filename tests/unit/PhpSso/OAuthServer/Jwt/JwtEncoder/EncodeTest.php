<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Jwt\JwtEncoder;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Encoding\Base64Url;
use PhpSso\OAuthServer\Jwt\JwtEncoder;
use PhpSso\OAuthServer\Jwt\StaticKeyProvider;
use PhpSso\OAuthServer\Tests\Support\TestKeys;

#[CoversMethod(JwtEncoder::class, 'encode')]
final class EncodeTest extends TestCase
{
    public function testItProducesAThreePartTokenWithTheKeyIdInTheHeader(): void
    {
        // Arrange
        $encoder = new JwtEncoder(new StaticKeyProvider(TestKeys::signingKey('key-1')));

        // Act
        $jwt = $encoder->encode(['sub' => 'user-1']);

        // Assert
        $parts = explode('.', $jwt);
        self::assertCount(3, $parts);
        $header = json_decode((string) Base64Url::decode($parts[0]), true);
        self::assertSame(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'key-1'], $header);
    }

    public function testItSetsTheTypeHeaderWhenGiven(): void
    {
        // Arrange
        $encoder = new JwtEncoder(new StaticKeyProvider(TestKeys::signingKey()));

        // Act
        $jwt = $encoder->encode(['sub' => 'user-1'], 'at+jwt');

        // Assert
        $header = json_decode((string) Base64Url::decode(explode('.', $jwt)[0]), true);
        self::assertIsArray($header);
        self::assertSame('at+jwt', $header['typ']);
    }

    public function testItEncodesNoClaimsAsAnEmptyObjectNotAList(): void
    {
        // Arrange
        $encoder = new JwtEncoder(new StaticKeyProvider(TestKeys::signingKey()));

        // Act
        $jwt = $encoder->encode([]);

        // Assert
        self::assertSame('{}', Base64Url::decode(explode('.', $jwt)[1]));
    }

    public function testItProducesTokensAnIndependentLibraryAccepts(): void
    {
        // Arrange
        $signingKey = TestKeys::signingKey('key-1');
        $encoder = new JwtEncoder(new StaticKeyProvider($signingKey));
        $jwt = $encoder->encode(['sub' => 'user-1', 'iss' => 'https://sso.example.com', 'url' => 'https://a/b']);
        $parser = new Parser(new JoseEncoder());
        $verificationKey = InMemory::plainText($signingKey->verificationKey()->publicKeyPem);

        // Act
        $token = $parser->parse($jwt);
        $valid = (new Validator())->validate($token, new SignedWith(new Sha256(), $verificationKey));

        // Assert
        self::assertTrue($valid);
        self::assertInstanceOf(UnencryptedToken::class, $token);
        self::assertSame('user-1', $token->claims()->get('sub'));
        self::assertSame('https://a/b', $token->claims()->get('url'));
    }
}
