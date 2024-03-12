<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Throwable;

interface ConstraintViolation extends Throwable
{
    public function getConstraintClass(): ?string;
}
