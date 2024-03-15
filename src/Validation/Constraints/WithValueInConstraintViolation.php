<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;

class WithValueInConstraintViolation extends Exception implements ConstraintViolation
{

    public function __construct(public readonly string $constraint,
                                public readonly string $key,
                                public readonly string $tokenSection,
                                public readonly array $allowedValues)
    {
        $allowedValuesString = implode(', ', array_map(fn($value) => strval($value), $this->allowedValues));

        $message = "Token $tokenSection value '$this->key' is not one of the following allowed values: $allowedValuesString";

        parent::__construct($message);
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
