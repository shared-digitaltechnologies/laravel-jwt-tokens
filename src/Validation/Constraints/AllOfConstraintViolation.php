<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Lcobucci\JWT\Validation\Constraint;

class AllOfConstraintViolation extends Exception implements ConstraintViolation
{
    /**
     * @param string $constraint
     * @param Constraint[] $constraints
     * @param ConstraintViolation[] $violations
     */
    public function __construct(public string $constraint, public array $constraints, public array $violations)
    {
        $constraintCount = count($this->constraints);
        $violationCount = count($this->violations);

        $message = "Token does satisfy $violationCount/$constraintCount constraints. details: ".PHP_EOL;

        foreach ($this->violations as $ix => $violation) {
            $violationMessage = str_replace("\n", "\n    ", $violation->getMessage());
            $message .= "[$ix]: $violationMessage".PHP_EOL;
        }

        parent::__construct($message);
    }

    public function getConstraintClass(): ?string
    {
        return $this->constraint;
    }
}
