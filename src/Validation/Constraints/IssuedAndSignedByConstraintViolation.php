<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Exception;
use Shrd\Laravel\JwtTokens\Contracts\IssuesTokens;

class IssuedAndSignedByConstraintViolation extends Exception implements ConstraintViolation
{
    /**
     * @param string $constraint
     * @param IssuesTokens[] $issuers
     * @param ConstraintViolation[] $violations
     */
    public function __construct(public string $constraint, public array $issuers, public array $violations)
    {
        $issuersCount = count($issuers);

        $message = "Token was not issued by one of the $issuersCount allowed issuers. details: ".PHP_EOL;

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
