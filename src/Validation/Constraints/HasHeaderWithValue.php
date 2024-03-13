<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;


use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

readonly class HasHeaderWithValue implements Constraint
{
    public function __construct(public string $header, public mixed $value)
    {
    }

    public function assert(Token $token): void
    {
        if(!$token->headers()->has($this->header)) {
            throw new \Lcobucci\JWT\Validation\ConstraintViolation(
                "Token is missing header '$this->header'",
                static::class
            );
        }

        $tokenValue = $token->headers()->get($this->header);

        if($tokenValue !== $this->value) {
            throw new \Lcobucci\JWT\Validation\ConstraintViolation(
                "Token header '$this->header' does not have the expected value.",
                static::class
            );
        }
    }
}
