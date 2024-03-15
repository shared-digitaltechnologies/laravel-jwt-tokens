<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Throwable;

class EmptyTokenLoaderException extends Exception implements InvalidJwtException
{
    public function __construct(?string $message = null, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
