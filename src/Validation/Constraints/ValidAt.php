<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use DateInterval;
use DateTimeInterface;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LeewayCannotBeNegative;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\ValidAt as ValidAtInterface;
use Lcobucci\JWT\Token;
use Psr\Clock\ClockInterface;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;

readonly class ValidAt implements ValidAtInterface, TimeConstraint
{
    private DateInterval $leeway;

    public function __construct(private ClockInterface $clock,
                                ?DateInterval $leeway = null,
                                protected bool $strict = true)
    {
        $this->leeway = $this->guardLeeway($leeway);
    }

    private function guardLeeway(?DateInterval $leeway): DateInterval
    {
        if ($leeway === null) {
            return new DateInterval('PT0S');
        }

        if ($leeway->invert === 1) {
            throw LeewayCannotBeNegative::create();
        }

        return $leeway;
    }

    public function assert(Token $token): void
    {
        if (! $token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass an unencrypted token', $this);
        }

        $now = $this->clock->now();

        $this->assertIssueTime($token, $now->add($this->leeway));
        $this->assertMinimumTime($token, $now->add($this->leeway));
        $this->assertExpiration($token, $now->sub($this->leeway));
    }

    /** @throws ConstraintViolation */
    private function assertExpiration(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if ($this->strict && !$token->claims()->has(Token\RegisteredClaims::EXPIRATION_TIME)) {
            throw ConstraintViolation::error('"Expiration Time" claim missing', $this);
        }

        if ($token->isExpired($now)) {
            throw ConstraintViolation::error('The token is expired', $this);
        }
    }

    /** @throws ConstraintViolation */
    private function assertMinimumTime(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if ($this->strict && !$token->claims()->has(Token\RegisteredClaims::NOT_BEFORE)) {
            throw ConstraintViolation::error('"Not Before" claim missing', $this);
        }

        if (!$token->isMinimumTimeBefore($now)) {
            throw ConstraintViolation::error('The token cannot be used yet', $this);
        }
    }

    /** @throws ConstraintViolation */
    private function assertIssueTime(UnencryptedToken $token, DateTimeInterface $now): void
    {
        if ($this->strict && !$token->claims()->has(Token\RegisteredClaims::ISSUED_AT)) {
            throw ConstraintViolation::error('"Issued At" claim missing', $this);
        }

        if (!$token->hasBeenIssuedBefore($now)) {
            throw ConstraintViolation::error('The token was issued in the future', $this);
        }
    }

    public function validDateRange(Token $token): DateRange
    {
        if(! $token instanceof UnencryptedToken) return DateRange::empty();

        if($this->strict
            && ( !$token->claims()->has(Token\RegisteredClaims::ISSUED_AT)
                || !$token->claims()->has(Token\RegisteredClaims::NOT_BEFORE)
                || !$token->claims()->has(Token\RegisteredClaims::EXPIRATION_TIME))) return DateRange::empty();

        return DateRange::fromBounds(
            $token->claims()->get(Token\RegisteredClaims::NOT_BEFORE),
            $token->claims()->get(Token\RegisteredClaims::EXPIRATION_TIME)
        );
    }
}
