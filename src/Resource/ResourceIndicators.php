<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Resource;

use PhpSso\OAuthServer\Client\Client;
use PhpSso\OAuthServer\Exception\OAuthException;
use PhpSso\OAuthServer\Http\Params;

/**
 * Resource indicators (RFC 8707): reads the `resource` parameter, which may repeat, and decides which resources an access token
 * is for. Without a {@see ResourcePolicy} the parameter is ignored.
 */
final readonly class ResourceIndicators
{
    public function __construct(private ?ResourcePolicy $policy)
    {
    }

    /**
     * The resources a request names, each checked to be an absolute URI without a fragment.
     *
     * @return list<string>
     *
     * @throws OAuthException invalid_target
     */
    public function requested(Params $params): array
    {
        if ($this->policy === null) {
            return [];
        }
        $resources = [];
        foreach ($params->repeated('resource') as $resource) {
            $parts = strlen($resource) <= 2048 && preg_match('/[\x00-\x20\x7F]/', $resource) !== 1 ? parse_url($resource) : false;
            if ($parts === false || !isset($parts['scheme']) || isset($parts['fragment']) || (in_array(strtolower($parts['scheme']), ['http', 'https'], true) && ($parts['host'] ?? '') === '')) {
                throw OAuthException::invalidTarget('A resource must be an absolute URI without a fragment.');
            }
            $resources[] = $resource;
        }

        return array_values(array_unique($resources));
    }

    /**
     * What an access token is for: the resources asked for now, or those the grant already had when none are asked for.
     * A request may narrow the grant but never widen it, and every resource must still be allowed to the client.
     *
     * @param list<string> $requested
     * @param list<string> $granted   what the authorization (code or refresh token) was for; empty when it named none
     *
     * @return list<string>
     *
     * @throws OAuthException invalid_target
     */
    public function resolve(array $requested, array $granted, Client $client): array
    {
        if ($this->policy === null) {
            return [];
        }
        $use = $requested === [] ? $granted : $requested;
        if ($granted !== [] && array_diff($use, $granted) !== []) {
            throw OAuthException::invalidTarget('A resource that the authorization did not name cannot be added later.');
        }
        foreach ($use as $resource) {
            if (!$this->policy->allows($client, $resource)) {
                throw OAuthException::invalidTarget("The resource {$resource} is not available to this client.");
            }
        }

        return $use;
    }
}
