<?php

namespace Shrd\Laravel\JwtTokens\Loaders;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\EmptyTokenLoaderException;
use Shrd\Laravel\JwtTokens\Validation\Constraints\EmptyConstraintViolation;

/**
 * A special token loader that will never load any token.
 */
readonly final class EmptyTokenLoader implements TokenLoader
{

    /**
     * @throws EmptyTokenLoaderException
     */
    public function parse(string $jwt): Token
    {
        throw new EmptyTokenLoaderException;
    }

    public function tryParse(?string $jwt): ?Token
    {
        return null;
    }

    public function check(Token|string $token): bool
    {
        return false;
    }

    public function validate(Token|string $token): Token
    {
        throw new EmptyTokenLoaderException;
    }

    public function validDateRange(Token|string $token): DateRange
    {
        return DateRange::empty();
    }

    public function load(string $jwt): UnencryptedToken
    {
        throw new EmptyTokenLoaderException;
    }

    public function tryLoad(string $jwt): ?UnencryptedToken
    {
        return null;
    }

    public function violations(Token $token): array
    {
        return [new EmptyConstraintViolation];
    }
}
