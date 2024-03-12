<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Lcobucci\JWT\Parser;
use Throwable;

class JwtParseException extends Exception implements InvalidJwtException
{
    public function __construct(public readonly Parser $parser,
                                public readonly string $jwt,
                                string $message = "",
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
