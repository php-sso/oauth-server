<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Endpoint;

use PhpSso\OAuthServer\Authorization\ScopeValidator;
use PhpSso\OAuthServer\Client\ClientAuthenticator;
use PhpSso\OAuthServer\Config\ServerConfig;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationRecord;
use PhpSso\OAuthServer\Grant\DeviceAuthorizationStore;
use PhpSso\OAuthServer\Grant\DeviceStatus;
use PhpSso\OAuthServer\Grant\GrantType;
use PhpSso\OAuthServer\Http\ErrorResponder;
use PhpSso\OAuthServer\Http\Params;
use PhpSso\OAuthServer\Http\Responses;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;
use PhpSso\OAuthServer\Token\TokenGenerator;
use PhpSso\OAuthServer\Token\TokenHash;
use PhpSso\OAuthServer\Token\UserCodeGenerator;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The device authorization endpoint (RFC 8628 section 3.1). A device without a browser or keyboard asks
 * here for a device code (to poll with) and a short user code (to show). The person approves the user
 * code on their phone through a page your application provides, using {@see \PhpSso\OAuthServer\Device\DeviceVerifier}.
 */
final readonly class DeviceAuthorizationHandler implements RequestHandlerInterface
{
    private const USER_CODE_ATTEMPTS = 5;

    public function __construct(
        private ServerConfig $config,
        private Endpoints $endpoints,
        private ClientAuthenticator $authenticator,
        private ScopeValidator $scopes,
        private DeviceAuthorizationStore $devices,
        private TokenGenerator $deviceCodes,
        private UserCodeGenerator $userCodes,
        private ClockInterface $clock,
        private Responses $responses,
        private ErrorResponder $errors,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            if ($request->getMethod() !== 'POST') {
                throw OAuthException::invalidRequest('The device authorization endpoint only accepts POST.');
            }
            $body = Params::fromBody($request);
            $client = $this->authenticator->authenticate($request, $body);
            if (!$client->allowsGrant(GrantType::DeviceCode)) {
                throw OAuthException::unauthorizedClient('This client may not use the device flow.');
            }
            $scopes = $this->scopes->validate($client, $body->string('scope'));
        } catch (OAuthException $e) {
            return $this->errors->respond($e);
        }

        $deviceCode = $this->deviceCodes->generate();
        $userCode = $this->freeUserCode();
        $this->devices->save(new DeviceAuthorizationRecord(
            TokenHash::of($deviceCode),
            TokenHash::of($userCode),
            $client->id(),
            $scopes,
            $this->deviceCodes->generate(),
            $this->clock->now()->getTimestamp() + $this->config->deviceCodeTtl,
            $this->config->deviceInterval,
            DeviceStatus::Pending,
            null,
            null,
            null,
            null,
        ));

        $verificationUri = Endpoints::url($this->config->issuer, $this->endpoints->deviceVerification);
        $formatted = RandomUserCodeGenerator::format($userCode);

        return $this->responses->noStore($this->responses->json([
            'device_code' => $deviceCode,
            'user_code' => $formatted,
            'verification_uri' => $verificationUri,
            'verification_uri_complete' => $verificationUri . (str_contains($verificationUri, '?') ? '&' : '?') . http_build_query(['user_code' => $formatted], '', '&', PHP_QUERY_RFC3986),
            'expires_in' => $this->config->deviceCodeTtl,
            'interval' => $this->config->deviceInterval,
        ]));
    }

    /** A user code nobody is currently using; at 2.5 * 10^10 combinations a clash is rare, but never ignored. */
    private function freeUserCode(): string
    {
        for ($attempt = 0; $attempt < self::USER_CODE_ATTEMPTS; ++$attempt) {
            $code = $this->userCodes->generate();
            if ($this->devices->findByUserCodeHash(TokenHash::of($code)) === null) {
                return $code;
            }
        }

        throw OAuthException::serverError('Could not allocate a user code.');
    }
}
