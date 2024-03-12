<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Illuminate\Validation\ValidationException;

class ValidationConstraintViolation extends ValidationException implements ConstraintViolation
{
    public function __construct(public readonly string $constraint, $validator, $response = null, $errorBag = 'default')
    {
        parent::__construct($validator, $response, $errorBag);
    }

    public function getConstraintClass(): string
    {
        return $this->constraint;
    }
}
