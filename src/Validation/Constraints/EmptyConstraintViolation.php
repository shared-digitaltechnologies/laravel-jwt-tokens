<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Throwable;

class EmptyConstraintViolation extends Exception implements ConstraintViolation
{
    public function __construct(public readonly ?string $constraint = null,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= "Every token will violate the empty constraint.";

        parent::__construct($message, $code, $previous);
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
