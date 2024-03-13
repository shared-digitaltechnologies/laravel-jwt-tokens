<?php

namespace Shrd\Laravel\JwtTokens\Keys\Loaders;

use Exception;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;
use Illuminate\Http\Client\Response;
use Safe\Exceptions\JsonException;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwksResponseException;
use Shrd\Laravel\JwtTokens\Exceptions\JwksUriNotFoundException;
use Shrd\Laravel\JwtTokens\Keys\Sets\JWKSet;

trait LoadsJWKsFromUrls
{
    protected abstract function http(): HttpFactory;

    /**
     * @throws RequestException
     * @throws Exception
     */
    protected function loadFromJWKsUri(string $jwks_uri): JWKSet
    {
        $response = $this->http()->get($jwks_uri)->throw();
        return $this->loadFromJWKsResponse($response);
    }

    /**
     * @throws JsonException
     * @throws InvalidJwksResponseException
     */
    protected function loadFromJWKsResponse(Response $response): JWKSet
    {
        $keys = $response->json('keys');

        if(!is_array($keys) || !array_is_list($keys)) {
            throw new InvalidJwksResponseException($response);
        }

        return JWKSet::fromJWKs($keys);
    }

    /**
     * @throws JwksUriNotFoundException
     * @throws RequestException
     */
    protected function loadFromOIDCMetadataResponse(Response $response): JWKSet
    {
        $jwks_uri = $response->json('jwks_uri');
        if($jwks_uri === null) {
            throw new JwksUriNotFoundException($response);
        }

        return $this->loadFromJWKsUri($jwks_uri);
    }

    /**
     * @throws RequestException
     * @throws JwksUriNotFoundException
     * @throws InvalidJwksResponseException
     * @throws JsonException
     */
    protected function loadFromOIDCOrJWKsResponse(Response $response): JWKSet
    {
        $keys = $response->json('keys');
        if($keys === null) {
            return $this->loadFromOIDCMetadataResponse($response);
        } else {
            return $this->loadFromJWKsResponse($response);
        }
    }

    /**
     * @throws JwksUriNotFoundException
     * @throws RequestException
     * @throws InvalidJwksResponseException
     * @throws JsonException
     */
    protected function loadFromOIDCOrJWKsUri(string $uri): JWKSet
    {
        $response = $this->http()->get($uri)->throw();
        return $this->loadFromOIDCOrJWKsResponse($response);
    }

    /**
     * @throws RequestException
     * @throws JwksUriNotFoundException
     */
    protected function loadFromOIDCMetadataEndpoint(string $metadata_uri): JWKSet
    {
        $response = $this->http()->get($metadata_uri)->throw();

        $jwks_uri = $response->json('jwks_uri');
        if($jwks_uri === null) {
            throw new JwksUriNotFoundException($response);
        }

        return $this->loadFromJWKsUri($jwks_uri);
    }
}
