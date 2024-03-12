<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use InvalidArgumentException;
use Throwable;

class UnsupportedAlgorithmException extends InvalidArgumentException implements JwtException
{
    public function __construct(public readonly string $alg,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Unsupported signer algorithm '$alg'";

        parent::__construct($message, $code, $previous);
    }
}
