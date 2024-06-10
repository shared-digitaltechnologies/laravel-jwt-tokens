<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Shrd\Laravel\JwtTokens\Contracts\IssuesTokens;

class NotIssuedByConstraintViolation extends Exception implements ConstraintViolation
{
    public function __construct(public string $constraint, protected IssuesTokens $issuesTokens)
    {
        $message = "Token was not issued by ".get_class($this->issuesTokens);

        parent::__construct($message);
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
