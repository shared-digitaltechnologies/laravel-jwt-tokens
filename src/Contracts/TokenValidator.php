<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Validation\Constraints\ConstraintViolation;

/**
 * @template T of Token
 */
interface TokenValidator
{
    /**
     * Gives the constraint violations of the provided token. Will be an empty array if the token is valid.
     *
     * @param Token $token
     * @return ConstraintViolation[]
     */
    public function violations(Token $token): array;

    /**
     * Checks if the provided token is a valid token.
     *
     * @param Token $token
     * @return bool
     */
    public function check(Token $token): bool;

    /**
     * Validates the provided token. Throws an InvalidJwtException if the token is invalid.
     *
     * @param Token $token
     * @return T&Token
     * @throws InvalidJwtException
     */
    public function validate(Token $token): Token;

    /**
     * Gives the date range in which the token is valid.
     *
     * @param Token $token
     * @return DateRange
     */
    public function validDateRange(Token $token): DateRange;
}
