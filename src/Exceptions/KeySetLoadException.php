<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Throwable;


class KeySetLoadException extends Exception implements KeySetException
{
    public function __construct(public readonly string $descriptor,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Failed to load key set from descriptor `$descriptor`";

        parent::__construct($message, $code, $previous);
    }
}
