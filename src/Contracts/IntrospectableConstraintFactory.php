<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use ReflectionParameter;

interface IntrospectableConstraintFactory extends ConstraintFactory
{
    public function has(string $constraint): bool;

    /**
     * @return string[]
     */
    public function constraintNames(): array;

    /**
     * @param string $constraint
     * @return ReflectionParameter[]
     */
    public function getConstraintParameters(string $constraint): array;
}
