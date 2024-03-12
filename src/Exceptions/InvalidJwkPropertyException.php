<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Shrd\Laravel\JwtTokens\Keys\JWK;
use Throwable;

class InvalidJwkPropertyException extends Exception implements InvalidKeySetException
{
    public function __construct(public readonly ?JWK $jwk,
                                public readonly string $property,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {

        $message ??= "Invalid JWK property with key '$property'.";

        parent::__construct($message, $code, $previous);
    }
}
