<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Exception;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintViolation;
use Throwable;

class TokenValidationException extends Exception implements InvalidJwtException
{
    /**
     * @param Token $token
     * @param Constraint[] $constraints
     * @param ConstraintViolation[] $violations
     * @param string|null $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(public readonly Token $token,
                                public readonly array $constraints,
                                public readonly array $violations,
                                ?string $message = null,
                                int $code = 0,
                                ?Throwable $previous = null)
    {
        $message ??= self::buildMessage($this->violations);

        parent::__construct($message, $code, $previous);
    }

    /** @param ConstraintViolation[] $violations */
    private static function buildMessage(array $violations): string
    {
        $violations = array_map(
            static function (ConstraintViolation $violation): string {
                $message = str_replace("\n", "\n    ", $violation->getMessage());

                return '  ['.$violation->getConstraintClass().']: ' . $message;
            },
            $violations,
        );

        $message  = "The token violates some mandatory constraints, details:\n";
        $message .= implode("\n", $violations);

        return $message;
    }
}
