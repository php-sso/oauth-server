<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Jwt;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PhpSso\OAuthServer\Encoding\Base64Url;

/** A public RSA key (at least 2048 bits) that signatures are checked against, identified by `kid`. */
final readonly class VerificationKey
{
    /** @var non-empty-string */
    public string $publicKeyPem;

    public function __construct(public string $kid, string $publicKeyPem)
    {
        if ($kid === '') {
            throw new InvalidArgumentException('A verification key needs a kid.');
        }
        if ($publicKeyPem === '') {
            throw new InvalidArgumentException('The verification key is empty.');
        }
        $this->publicKeyPem = $publicKeyPem;
        $this->details(); // throws unless it is an RSA public key of at least 2048 bits
    }

    /**
     * Builds a key from a JSON Web Key as found in a JWKS document.
     *
     * @param array<string, mixed> $jwk
     */
    public static function fromJwk(array $jwk): self
    {
        $kid = $jwk['kid'] ?? null;
        $n = $jwk['n'] ?? null;
        $e = $jwk['e'] ?? null;
        if (($jwk['kty'] ?? null) !== 'RSA' || !is_string($kid) || !is_string($n) || !is_string($e)) {
            throw new InvalidArgumentException('Only RSA keys with kid, n and e are supported.');
        }
        $modulus = Base64Url::decode($n);
        $exponent = Base64Url::decode($e);
        if ($modulus === null || $exponent === null || $modulus === '' || $exponent === '') {
            throw new InvalidArgumentException('The key parameters are not valid base64url.');
        }

        $integers = self::der(0x30, self::derInteger($modulus) . self::derInteger($exponent));
        $algorithm = self::der(0x30, self::der(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") . "\x05\x00"); // rsaEncryption, NULL
        $spki = self::der(0x30, $algorithm . self::der(0x03, "\x00" . $integers));
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";

        return new self($kid, $pem);
    }

    /** @return array{kty: string, use: string, alg: string, kid: string, n: string, e: string} */
    public function toJwk(): array
    {
        $details = $this->details();

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->kid,
            'n' => Base64Url::encode($details->modulus),
            'e' => Base64Url::encode($details->exponent),
        ];
    }

    /** @internal for the verifier */
    public function openSslKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_get_public($this->publicKeyPem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException('The verification key cannot be read.');
        }

        return $key;
    }

    private function details(): RsaKeyDetails
    {
        $key = openssl_pkey_get_public($this->publicKeyPem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException('The verification key is not a readable public key in PEM format.');
        }

        return RsaKeyDetails::of($key);
    }

    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        $bytes = $bytes === '' ? "\x00" : $bytes;
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes; // keep it positive
        }

        return self::der(0x02, $bytes);
    }

    private static function der(int $tag, string $content): string
    {
        $length = strlen($content);
        $encoded = $length < 0x80 ? chr($length) : chr(0x80 | strlen(ltrim(pack('N', $length), "\x00"))) . ltrim(pack('N', $length), "\x00");

        return chr($tag) . $encoded . $content;
    }
}
