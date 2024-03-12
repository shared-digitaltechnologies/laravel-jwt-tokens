<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Lcobucci\JWT\Validation\ConstraintViolation as BaseConstraintViolation;

class WrappedConstraintViolation extends Exception implements ConstraintViolation
{
    public function __construct(public readonly BaseConstraintViolation $wrapped)
    {
        parent::__construct($wrapped->getMessage(), $wrapped->code, $wrapped);
    }


    public function getConstraintClass(): ?string
    {
        return $this->wrapped->constraint;
    }
}
