<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;

class MissingMandatoryValuesViolation extends Exception implements ConstraintViolation
{
    public function __construct(public readonly string $constraint,
                                public readonly string $tokenSection,
                                public readonly array $missing)
    {

        parent::__construct("Missing mandatory $this->tokenSection: ".implode(', ', $this->missing));
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
