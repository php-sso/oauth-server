<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Jwt\Jwks;
use PhpSso\OAuthServer\Jwt\KeyProvider;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** Publishes the public keys clients and APIs verify tokens with. */
final readonly class JwksHandler implements RequestHandlerInterface
{
    public function __construct(private KeyProvider $keys, private Responses $responses)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responses->json(Jwks::toArray($this->keys), 200, ['Cache-Control' => 'public, max-age=300']);
    }
}
