<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

readonly class OneOf implements Constraint
{
    /**
     * @param Constraint[] $constraints
     */
    public function __construct(protected array $constraints)
    {
    }

    /**
     * @throws OneOfConstraintViolation
     */
    public function assert(Token $token): void
    {
        $violations = [];

        foreach ($this->constraints as $ix => $constraint) {
            try {
                $constraint->assert($token);
                return;
            } catch (\Lcobucci\JWT\Validation\ConstraintViolation $violation) {
                $violations[$ix] = new WrappedConstraintViolation($violation);
            }
        }

        throw new OneOfConstraintViolation(static::class, $this->constraints, $violations);
    }
}
