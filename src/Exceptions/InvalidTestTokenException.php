<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Loaders\TestTokenLoader;

class InvalidTestTokenException extends Exception implements InvalidJwtException
{

    public readonly string $jwt;

    public function __construct(public readonly string|Token $token, public readonly TestTokenLoader $loader)
    {
        $this->jwt = is_string($token) ? $token : $token->toString();

        $message = "Token '$this->jwt' is not one of the registered test tokens.";

        parent::__construct($message);
    }
}
