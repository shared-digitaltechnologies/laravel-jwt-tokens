<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;
use Throwable;

class ClaimMissingException extends Exception implements JwtException
{
    public function __construct(public readonly string $claimName,
                                public readonly ClaimsBag $claims,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Claim '$this->claimName' missing";

        parent::__construct($message, $code, $previous);
    }
}
