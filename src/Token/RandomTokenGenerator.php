<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Token;

use PhpSso\OAuthServer\Encoding\Base64Url;

/** 256 bits from the operating system's random source, base64url encoded (43 characters). */
final class RandomTokenGenerator implements TokenGenerator
{
    public function generate(): string
    {
        return Base64Url::encode(random_bytes(32));
    }
}
