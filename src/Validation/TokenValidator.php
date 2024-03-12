<?php

namespace Shrd\Laravel\JwtTokens\Validation;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation as LcobucciConstraintViolation;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Exceptions\TokenValidationException;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintViolation;
use Shrd\Laravel\JwtTokens\Validation\Constraints\WrappedConstraintViolation;

/**
 * @method $this validAt(bool $strict = true, $leeway = null)
 * @method $this hasClaims(string ...$names)
 * @method $this hasClaimWithValue(string $claim, mixed $value)
 * @method $this hasHeaders(string ...$names)
 * @method $this hasKeyId()
 * @method $this identifiedBy(string $tid)
 * @method $this issuedBy(string ...$issuers)
 * @method $this permittedFor(?string $audience = null)
 * @method $this relatedTo(string $subject)
 * @method $this signedWith(string ...$keySets)
 * @method $this signedUsing(string|Algorithm ...$algorithms)
 * @method $this verifyWith(Verifier $verifier)
 */
class TokenValidator
{
    protected array $constraints = [];

    /**
     * @var ConstraintViolation[]
     */
    protected array $violations = [];

    public function __construct(protected readonly Token $token,
                                protected readonly ConstraintFactory $constraintFactory)
    {
    }

    public function constraints(): array
    {
        return $this->constraints;
    }

    public function violations(): array
    {
        return $this->violations;
    }

    public function fails(): bool
    {
        return count($this->constraints) === 0 || count($this->violations) > 0;
    }

    public function isValid(): bool
    {
        return !$this->fails();
    }

    /**
     * @throws TokenValidationException
     */
    public function validate(): Token
    {
        if($this->fails()) {
            throw new TokenValidationException($this, $this->violations);
        } else {
            return $this->token;
        }
    }

    protected function constraint(Constraint $constraint): static
    {
        $this->constraints[] = $constraint;
        try {
            $constraint->assert($this->token);
        } catch (LcobucciConstraintViolation $violation) {
            $this->violations[] = new WrappedConstraintViolation($violation);
        } catch (ConstraintViolation $violation) {
            $this->violations[] = $violation;
        }
        return $this;
    }

    public function callback(callable $callback, ?string $message = null): static
    {
        return $this->constraint(
            $this->constraintFactory->createCallbackConstraint($callback, $message)
        );
    }

    public function claimRules(array $rules, array $messages = [], array $attributes = []): static
    {
        return $this->constraint(
            $this->constraintFactory->createClaimRulesConstraint($rules, $messages, $attributes)
        );
    }

    public function rules(array $rules, array $messages = [], array $attributes = []): static
    {
        return $this->constraint(
            $this->constraintFactory->createClaimRulesConstraint($rules, $messages, $attributes)
        );
    }

    public function headerRules(array $rules, array $messages = [], array $attributes = []): static
    {
        return $this->constraint(
            $this->constraintFactory->createHeaderRulesConstraint($rules, $messages, $attributes)
        );
    }

    public function and(string|array|callable|Constraint $constraint, ...$arguments): static
    {
        if($constraint instanceof Constraint) {
            $this->constraint($constraint);
            foreach ($arguments as $argument) {
                $this->constraint($argument);
            }
            return $this;
        }

        if(is_string($constraint)) return $this->constraint(
            $this->constraintFactory->create($constraint, ...$arguments)
        );

        if(is_array($constraint)) return $this->claimRules($constraint, ...$arguments);

        return $this->constraint($constraint);
    }

    public function if(bool|callable $condition, string|array|callable|Constraint $constraint, ...$arguments): static
    {
        if(is_callable($condition)) $condition = $condition($this->token);

        if($condition) {
            $this->and($constraint, $arguments);
        }

        return $this;
    }

    public function __call(string $name, array $arguments): static
    {
        return $this->constraint(
            $this->constraintFactory->create($name, ...$arguments)
        );
    }

    public function __invoke(string|array|callable|Constraint $constraint, ...$arguments): static
    {
        return $this->and($constraint, ...$arguments);
    }

}
