<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Http;

use PhpSso\OAuthServer\Exception\OAuthException;
use Psr\Http\Message\ResponseInterface;

/** RFC 6749 section 5.2 error responses: JSON, never cached, with the challenge headers the RFCs require. */
final readonly class JsonErrorResponder implements ErrorResponder
{
    public function __construct(private Responses $responses)
    {
    }

    public function respond(OAuthException $error): ResponseInterface
    {
        $headers = [];
        if ($error->error === 'invalid_client' && $error->httpStatus === 401) {
            $headers['WWW-Authenticate'] = 'Basic realm="oauth", charset="UTF-8"';
        }
        if ($error->error === 'invalid_token' || $error->error === 'insufficient_scope') {
            $headers['WWW-Authenticate'] = sprintf(
                'Bearer error="%s", error_description="%s"',
                $error->error,
                str_replace(['\\', '"'], ['\\\\', '\\"'], $error->errorDescription),
            );
        }

        return $this->responses->noStore($this->responses->json($error->toArray(), $error->httpStatus, $headers));
    }
}
