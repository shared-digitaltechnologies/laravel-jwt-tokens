<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Shrd\Laravel\JwtTokens\Keys\JWK;
use Throwable;

class UnsupportedKeyTypeException extends Exception implements KeySetException
{
    public function __construct(public readonly ?JWK $jwk,
                                public readonly ?string $kty,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Unsupported key-type (kty) '$kty'.";

        parent::__construct($message, $code, $previous);
    }
}
