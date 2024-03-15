<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;

class TestConstraintViolation extends Exception implements ConstraintViolation
{
    public readonly string $constraint;

    public function __construct(?string $message = null, ?string $constraint = null)
    {
        $message ??= "Test constraint violation";
        $this->constraint = $constraint ?? TestConstraint::class;

        parent::__construct($message);
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
