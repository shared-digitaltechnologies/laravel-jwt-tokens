<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

readonly class HasClaims implements Constraint
{

    public function __construct(public array $names)
    {
    }

    /**
     * @throws MissingMandatoryValuesViolation
     */
    public function assert(Token $token): void
    {
        $missing = [];
        foreach ($this->names as $name) {
            if(!$token->claims()->has($name)) $missing[] = $name;
        }

        if(count($missing) > 0) {
            throw new MissingMandatoryValuesViolation(static::class, 'claims', $missing);
        }


    }
}
