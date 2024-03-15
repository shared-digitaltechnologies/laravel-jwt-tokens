<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

class AllOf implements TimeConstraint
{
    /**
     * @param Constraint[] $constraints
     */
    public function __construct(protected array $constraints)
    {
    }

    /**
     * @throws AllOfConstraintViolation
     */
    public function assert(Token $token): void
    {
        $violations = [];

        foreach ($this->constraints as $ix => $constraint) {
            try {
                $constraint->assert($token);
            } catch (ConstraintViolation $violation) {
                $violations[$ix] = $violation;
            } catch (\Lcobucci\JWT\Validation\ConstraintViolation $violation) {
                $violations[$ix] = new WrappedConstraintViolation($violation);
            }
        }

        if(count($violations) > 0) {
            throw new AllOfConstraintViolation(static::class, $this->constraints, $violations);
        }
    }

    public function validDateRange(Token $token): DateRange
    {
        $result = DateRange::unbounded();
        foreach ($this->constraints as $constraint) {
            if($constraint instanceof TimeConstraint) {
                $result = $result->intersect($constraint->validDateRange($token));
            } else {
                try {
                    $constraint->assert($token);
                } catch (Exception) {
                    return DateRange::unbounded();
                }
            }
        }
        return $result;
    }
}
