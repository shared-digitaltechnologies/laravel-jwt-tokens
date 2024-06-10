<?php

namespace Shrd\Laravel\JwtTokens\Validation;

use Closure;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Contracts\IssuesTokens;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Validation\Constraints\AllOf;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConditionalConstraint;
use Shrd\Laravel\JwtTokens\Validation\Constraints\OneOf;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;

/**
 * @method $this validAt(bool $strict = true, $leeway = null)
 * @method $this hasClaims(string ...$names)
 * @method $this claimRules(array $rules, array $messages = [], array $attributes = [])
 * @method $this hasClaimWithValue(string $claim, mixed $value)
 * @method $this hasClaimWithValueIn(string $claim, iterable $values)
 * @method $this claimValuesIn(string $claim, iterable $values)
 * @method $this headerRules(array $rules, array $messages = [], array $attributes = [])
 * @method $this hasHeaders(string ...$names)
 * @method $this hasHeaderWithValue(string $claim, mixed $value)
 * @method $this hasHeaderWithValueIn(string $claim, iterable $values)
 * @method $this hasKeyId()
 * @method $this identifiedBy(string $tid)
 * @method $this issuedBy(string ...$issuers)
 * @method $this permittedFor(?string $audience = null)
 * @method $this relatedTo(string $subject)
 * @method $this signedWith(string ...$keySets)
 * @method $this signedUsing(string|Algorithm ...$algorithms)
 * @method $this issuedAndSignedBy(IssuesTokens ...$issuers)
 * @method $this verifyWith(Verifier $verifier)
 * @method $this hasNonceValue(string $value)
 * @method $this callback(callable $callback, ?string $message = null)
 * @method $this always()
 */
class Builder implements TokenValidator
{
    /**
     * @var Constraint[] $constraints
     */
    protected array $constraints = [];

    /**
     * @param ConstraintFactory $constraintFactory
     */
    public function __construct(protected readonly ConstraintFactory $constraintFactory)
    {
    }

    /**
     * @param string|callable(self $builder): (void|self)|self|array|Constraint $constraint
     * @param ...$arguments
     * @return Constraint
     */
    protected function prepareConstraint(string|callable|self|array|Constraint $constraint, ...$arguments): Constraint
    {
        if($constraint instanceof Constraint) {
            return $constraint;
        }

        if(is_string($constraint)) {
            return $this->constraintFactory->create($constraint, ...$arguments);
        }

        if(is_array($constraint)) {
            return $this->prepareConstraint(...$constraint);
        }

        if($constraint instanceof self) {
            return $constraint->toConstraint();
        }

        return $this->createSubBuilderCallbackConstraint($constraint);

    }

    /**
     * @param callable(self $builder): (void|self) $callback
     * @return Constraint
     */
    protected function createSubBuilderCallbackConstraint(callable $callback): Constraint
    {
        $subBuilder = new self($this->constraintFactory);

        $result = $callback($subBuilder);

        if($result instanceof self) {
            $subBuilder = $result;
        }

        return $subBuilder->toConstraint();
    }


    protected function addConstraint(Constraint $constraint): static
    {
        $this->constraints[] = $constraint;
        return $this;
    }

    /**
     * Generates a new constraint for the validator.
     *
     * @param string|callable(self $builder): void|self|array|Constraint $constraint
     * @param ...$arguments
     * @return $this
     */
    public function add(string|callable|self|array|Constraint $constraint, ...$arguments): static
    {
        if(is_string($constraint)) {
            $this->addConstraint($this->prepareConstraint($constraint, ...$arguments));
        } else {
            $this->addConstraint($this->prepareConstraint($constraint));
            if(count($arguments) > 0) {
                // Return here to make it tail recursive (no idea if PHP actually optimises for this though...)
                return $this->add(...$arguments);
            }
        }

        return $this;
    }

    /**
     * Asserts that at least one of the provided constraints passes.
     *
     * You may use named properties for the cases. These names will be shown in error messages.
     *
     * @param callable|Builder|array|Constraint ...$constraints
     * @return $this
     */
    public function oneOf(callable|self|array|Constraint ...$constraints): static
    {
        $resultConstraints = [];

        foreach ($constraints as $ix => $constraintInput) {
            $resultConstraints[$ix] = $this->prepareConstraint($constraintInput);
        }

        $this->addConstraint(new OneOf($resultConstraints));

        return $this;
    }

    /**
     * Applies a constraint iff the condition is true.
     *
     * @param bool|(callable(Token $token): bool) $condition
     * @param string|callable|self|array|Constraint $constraint
     * @param ...$arguments
     * @return $this
     */
    public function if(bool|callable $condition,
                       string|callable|self|array|Constraint $constraint,
                       ...$arguments): static
    {
        if(is_bool($condition)) {
            if($condition) {
                $this->add($constraint, ...$arguments);
            }
            return $this;
        }

        if(!($condition instanceof Closure)) {
            $condition = $condition(...);
        }

        if(is_string($constraint)) {
            $this->addConstraint(new ConditionalConstraint(
                condition: $condition,
                constraint: $this->prepareConstraint($constraint, ...$arguments)
            ));
        } else {
            $this->addConstraint(new ConditionalConstraint(
                condition: $condition,
                constraint: $this->prepareConstraint($constraint)
            ));

            if(count($arguments) > 0) {
                // Return here to make it tail recursive (no idea if PHP actually optimises for this though...)
                return $this->if($condition, ...$arguments);
            }
        }

        return $this;
    }

    /**
     * Returns the constraints for a validator created by this builder.
     *
     * @return Constraint[]
     */
    public function constraints(): array
    {
        return $this->constraints;
    }

    public function toConstraint(): Constraint
    {
        return new AllOf($this->constraints);
    }

    public function validator(): Validator
    {
        return new Validator($this->constraints);
    }

    public function violations(Token $token): array
    {
        return $this->validator()->violations($token);
    }

    public function check(Token $token): bool
    {
        return $this->validator()->check($token);
    }

    public function validate(Token $token): Token
    {
        return $this->validator()->validate($token);
    }

    public function validDateRange(Token $token): DateRange
    {
        return $this->validator()->validDateRange($token);
    }

    public function __call(string $name, array $arguments): static
    {
        return $this->add($name, ...$arguments);
    }
}
