<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Support;

use Laminas\Diactoros\Response\HtmlResponse;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\ErrorResponder;
use Psr\Http\Message\ResponseInterface;

/** Answers with a page instead of JSON, as an application's own error screen would. */
final class PageErrorResponder implements ErrorResponder
{
    public function respond(OAuthException $error): ResponseInterface
    {
        return new HtmlResponse('<h1>' . htmlspecialchars($error->errorDescription) . '</h1>', $error->httpStatus);
    }
}
