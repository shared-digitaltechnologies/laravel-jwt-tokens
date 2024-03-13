<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Validation\Constraint;

/**
 * Factory to create token constraints that are used in the token validator.
 */
interface ConstraintFactory
{
    public function create(string $constraint,
                           ...$arguments): Constraint;

    public function createCallbackConstraint(callable $callback,
                                             ?string $message = null): Constraint;

    public function createClaimRulesConstraint(array $rules,
                                               array $messages = [],
                                               array $attributes = []): Constraint;

    public function createHeaderRulesConstraint(array $rules,
                                                array $messages = [],
                                                array $attributes = []): Constraint;

    public function extend(string|object $constraint,
                           callable|Constraint|null $callback = null): static;
}
