<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Illuminate\Http\Client\HttpClientException;
use Illuminate\Http\Client\Response;
use Throwable;

class InvalidJwksResponseException extends HttpClientException implements JwtException
{
    public function __construct(public readonly Response $response,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Invalid jwks response";

        parent::__construct($message, $code, $previous);
    }
}
