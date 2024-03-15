<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

readonly class OneOf implements TimeConstraint
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

    public function validDateRange(Token $token): DateRange
    {
        $result = DateRange::empty();

        foreach ($this->constraints as $constraint) {
            if($constraint instanceof TimeConstraint) {
                $result->span($constraint->validDateRange($token));
            } else {
                try {
                    $constraint->assert($token);
                    return DateRange::unbounded();
                } catch (Exception) {}
            }
        }
        return $result;
    }
}
