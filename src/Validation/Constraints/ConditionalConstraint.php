<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Closure;
use Exception;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

class ConditionalConstraint implements TimeConstraint
{
    /**
     * @param Closure(Token $token): bool $condition
     * @param Constraint $constraint
     */
    public function __construct(protected Closure $condition, protected Constraint $constraint)
    {
    }

    public function appliesTo(Token $token): bool
    {
        return ($this->condition)($token);
    }

    public function assert(Token $token): void
    {
        if($this->appliesTo($token)) {
            $this->constraint->assert($token);
        }
    }

    public function validDateRange(Token $token): DateRange
    {
        if($this->appliesTo($token)) {
            return DateRange::unbounded();
        }

        if($this->constraint instanceof TimeConstraint) {
            return $this->constraint->validDateRange($token);
        } else {
            try {
                $this->constraint->assert($token);
                return DateRange::unbounded();
            } catch (Exception) {
                return DateRange::empty();
            }
        }
    }
}
