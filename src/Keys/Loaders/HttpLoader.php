<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Exception;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;
use Shrd\Laravel\JwtTokens\Contracts\KeySetLoader;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;

class HttpLoader implements KeySetLoader
{
    use LoadsJWKsFromUrls;

    public function __construct(protected HttpFactory $http)
    {
    }

    /**
     * @throws RequestException
     * @throws Exception
     */
    public function loadKeySet(string $descriptor, array $config): KeySet
    {
        return $this->loadFromOIDCOrJWKsUri($descriptor);
    }

    protected function http(): HttpFactory
    {
        return $this->http;
    }
}
