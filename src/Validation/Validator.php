<?php

namespace Shrd\Laravel\JwtTokens\Validation;

use ArrayIterator;
use Countable;
use IteratorAggregate;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Exceptions\TokenValidationException;
use Shrd\Laravel\JwtTokens\Validation\Constraints\AllOf;
use Shrd\Laravel\JwtTokens\Validation\Constraints\AllOfConstraintViolation;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintViolation;
use Shrd\Laravel\JwtTokens\Validation\Constraints\TimeConstraint;
use Shrd\Laravel\JwtTokens\Validation\Constraints\WrappedConstraintViolation;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;
use Traversable;

/**
 * @template T of Token
 * @implements IteratorAggregate<array-key, Constraint>
 * @implements TokenValidator<T>
 */
readonly class Validator implements IteratorAggregate, Countable, TimeConstraint, TokenValidator
{
    /**
     * @param Constraint[] $constraints
     */
    public function __construct(protected array $constraints)
    {
    }

    /**
     * Creates the empty constraint validator.
     *
     * @return self
     */
    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * Returns the constraints of this validator.
     *
     * @return Constraint[]
     */
    public function constraints(): array
    {
        return $this->constraints();
    }

    /**
     * Applies all constraints to the token and returns an array of constraint violations.
     *
     * @noinspection PhpRedundantCatchClauseInspection
     * @return ConstraintViolation[]
     */
    public function violations(Token $token): array
    {
        $violations = [];

        foreach ($this->constraints as  $constraint) {
            try {
                $constraint->assert($token);
            } catch (ConstraintViolation $violation) {
                $violations[] = $violation;
            } catch (\Lcobucci\JWT\Validation\ConstraintViolation $violation) {
                $violations[] = new WrappedConstraintViolation($violation);
            }
        }

        return $violations;
    }

    /**
     * Checks if the provided token is valid.
     *
     * It will immediately return `false` if one of the constraints is violated.
     *
     * @noinspection PhpRedundantCatchClauseInspection
     */
    public function check(Token $token): bool
    {
        foreach ($this->constraints as $constraint) {
            try {
                $constraint->assert($token);
            } catch (ConstraintViolation|\Lcobucci\JWT\Validation\ConstraintViolation) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param Token $token
     * @return T&Token
     * @throws TokenValidationException
     */
    public function validate(Token $token): Token
    {
        $violations = $this->violations($token);

        if(count($violations) > 0) {
            throw new TokenValidationException(
                token: $token,
                constraints: $this->constraints,
                violations: $violations
            );
        }

        return $token;
    }

    /**
     * @throws TokenValidationException
     * @throws JwtParseException
     */
    public function __invoke(Token $token): Token
    {
        return $this->validate($token);
    }

    /**
     * Asserts that the token passes all constraints of this validator.
     *
     * This method allows this validator to be used as a constraint.
     *
     * @throws AllOfConstraintViolation
     */
    public function assert(Token $token): void
    {
        (new AllOf($this->constraints))->assert($token);
    }

    /**
     * Gives the date range in which the provided token is valid.
     *
     * @param Token $token
     * @return DateRange
     */
    public function validDateRange(Token $token): DateRange
    {
        return (new AllOf($this->constraints))->validDateRange($token);
    }

    /**
     * Whether this validator has no constraints.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->count() === 0;
    }

    /**
     * Counts the number of constraints in this validator.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->constraints);
    }

    /**
     * Iterates over the constraints of this validator.
     *
     * @return Traversable<array-key, Constraint>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->constraints);
    }



}
