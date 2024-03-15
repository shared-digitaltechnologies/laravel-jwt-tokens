<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

readonly class TestConstraint implements TimeConstraint
{
    public ?ConstraintViolation $violation;

    public ?DateRange $dateRange;

    public function __construct(string|null|ConstraintViolation $violation = null, ?DateRange $dateRange = null)
    {
        $this->violation = is_string($violation)
            ? new TestConstraintViolation($violation, static::class)
            : $violation;

        $this->dateRange = $dateRange;
    }

    /**
     * @throws ConstraintViolation
     * @throws TestConstraintViolation
     */
    public function assert(Token $token): void
    {
        if($this->violation !== null) throw $this->violation;
    }

    public function validDateRange(Token $token): DateRange
    {
        if($this->dateRange !== null) return $this->dateRange;

        if($this->violation !== null) return DateRange::empty();

        if(!($token instanceof UnencryptedToken)) return DateRange::unbounded();

        return DateRange::fromBounds(
            lowerBound: $token->claims()->get('nbf'),
            upperBound: $token->claims()->get('exp')
        );
    }
}
