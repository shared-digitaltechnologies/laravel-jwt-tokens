<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

interface TimeConstraint extends Constraint
{
    public function validDateRange(Token $token): DateRange;
}
