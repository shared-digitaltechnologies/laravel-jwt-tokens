<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

readonly class Always implements Constraint
{

    public function assert(Token $token): void
    {
    }
}
