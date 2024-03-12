<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Exception;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\JWKSet;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

class HttpLoader implements KeySetLoader
{
    public function __construct(protected HttpFactory $http)
    {
    }

    /**
     * @throws RequestException
     * @throws Exception
     */
    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        $response = $this->http->get($descriptor)->throw();
        $keys = $response->json('keys');

        // Handle openid well=known response.
        if($keys === null) {
            $jwks_uri = $response->json('jwks_uri');
            if($jwks_uri === null) {
                throw new Exception('Invalid keys response.');
            }

            $response = $this->http->get($jwks_uri)->throw();
            $keys = $response->json('keys');
        }

        if(!is_array($keys) || !array_is_list($keys)) {
            throw new Exception('Invalid keys response.');
        }

        return JWKSet::fromJWKs($keys);
    }
}
