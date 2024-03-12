<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Validation\TokenValidator;

/**
 * Constructs new token validator instances.
 */
interface TokenValidatorFactory
{
    public function validate(Token $token): TokenValidator;
}
