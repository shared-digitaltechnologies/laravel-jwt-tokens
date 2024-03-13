<?php

namespace Shrd\Laravel\JwtTokens\Validation;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation as LcobucciConstraintViolation;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Contracts\ConstraintFactory;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidatorFactory;
use Shrd\Laravel\JwtTokens\Exceptions\TokenValidationException;
use Shrd\Laravel\JwtTokens\Signers\Verifier;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintViolation;
use Shrd\Laravel\JwtTokens\Validation\Constraints\WrappedConstraintViolation;

/**
 * @method $this validAt(bool $strict = true, $leeway = null)
 * @method $this hasClaims(string ...$names)
 * @method $this hasClaimWithValue(string $claim, mixed $value)
 * @method $this hasHeaderWithValue(string $claim, mixed $value)
 * @method $this hasHeaders(string ...$names)
 * @method $this hasKeyId()
 * @method $this identifiedBy(string $tid)
 * @method $this issuedBy(string ...$issuers)
 * @method $this permittedFor(?string $audience = null)
 * @method $this relatedTo(string $subject)
 * @method $this signedWith(string ...$keySets)
 * @method $this signedUsing(string|Algorithm ...$algorithms)
 * @method $this verifyWith(Verifier $verifier)
 * @method $this hasNonceValue(string $value)
 * @method $this oneOf(Constraint|array ...$constraints)
 * @method $this always()
 */
class TokenValidator
{
    /**
     * @var Constraint[] $constraints
     */
    protected array $constraints = [];

    /**
     * @var ConstraintViolation[] $violations
     */
    protected array $violations = [];

    public function __construct(protected readonly Token $token,
                                protected readonly ConstraintFactory $constraintFactory)
    {
    }

    /**
     * Constructs a new token validator using the @see TokenValidatorFactory of the application container. This method
     * requires the laravel application to be initialized.
     *
     * @param Token $token
     * @return self
     */
    public static function make(Token $token): self
    {
        return app(TokenValidatorFactory::class)->validate($token);
    }

    /**
     * Returns the constraints that were applied to the token.
     *
     * @return Constraint[]
     */
    public function constraints(): array
    {
        return $this->constraints;
    }

    /**
     * Returns `true` if some constraints were violated.
     *
     * @return bool
     */
    public function fails(): bool
    {
        return count($this->violations) > 0;
    }

    /**
     * Returns the constraint violations thrown by the constraints.
     *
     * @return ConstraintViolation[]
     */
    public function violations(): array
    {
        return $this->violations;
    }

    /**
     * Returns `true` if the token passed all generated constraints.
     *
     * @return bool
     */
    public function isValid(): bool
    {
        return !$this->fails();
    }

    /**
     * @throws TokenValidationException
     */
    public function validate(): Token
    {
        if(count($this->violations) > 0) {
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

    /**
     * Generates a new constraint and applies it to the token.
     *
     * @param string|array|callable|Constraint $constraint
     * @param ...$arguments
     * @return $this
     */
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

        if(is_callable($constraint)) return $this->callback($constraint, ...$arguments);

        return $this->constraint($constraint);
    }

    /**
     * Applies a constraint iff the condition is true.
     *
     * @param bool|(callable(Token $token): bool) $condition
     * @param string|array|callable|Constraint $constraint
     * @param ...$arguments
     * @return $this
     */
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
