<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Shrd\Laravel\JwtTokens\Tokens\Token;
use Shrd\Laravel\JwtTokens\Validation\TokenValidator;

interface TokenValidatorFactory
{
    public function validate(string|Token $token): TokenValidator;
}
