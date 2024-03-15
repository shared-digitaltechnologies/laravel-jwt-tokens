<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;

/**
 * @template T of Token
 * @implements TokenValidator<T>
 */
interface TokenLoader extends TokenValidator
{
    /**
     * Only parses the provided jwt string.
     *
     * @param string $jwt
     * @return T&Token
     * @throws JwtParseException
     */
    public function parse(string $jwt): Token;

    /**
     * Only parses the provided jwt string. Returns `null` if the token was invalid.
     *
     * @param string $jwt
     * @return (T&Token)|null
     */
    public function tryParse(string $jwt): ?Token;

    /**
     * Checks if the provided jwt can be parsed and is valid.
     *
     * @param string|Token $token
     * @return bool
     */
    public function check(string|Token $token): bool;

    /**
     * Parses a jwt string if needed and validates the token. Throws an InvalidJwtException if the token could not be
     * parsed or if it violates some constraints.
     *
     * @param string|Token $token
     * @return T&Token
     * @throws InvalidJwtException
     */
    public function validate(string|Token $token): Token;

    /**
     * Gives the date range in which the token is valid.
     *
     * @param string|Token $token
     * @return DateRange
     */
    public function validDateRange(string|Token $token): DateRange;

    /**
     * Returns a validated and unencrypted token instance from a jwt string if that token is valid. How the loader
     * does this determined by the implementation, but it should at least ensure the following properties about the
     * token:
     *
     *  1. The jwt string MUST be a valid jwt string. Otherwise, it should throw an InvalidJwtException.
     *  2. The parsed jwt MUST have been validated at some point before the token is returned. It MAY have be validated
     *     in some earlier request, in which case it should return the cached result of that request.
     *  3. The returned token MUST be a valid token at the current timestamp. If the token expired, it should throw
     *     an InvalidJwtException.
     *
     * @param string $jwt
     * @return UnencryptedToken
     * @throws InvalidJwtException
     */
    public function load(string $jwt): UnencryptedToken;

    /**
     * Tries to load the provided jwt string like the `load` method, but returns `null` if the loading failed.
     *
     * @param string $jwt
     * @return UnencryptedToken|null
     */
    public function tryLoad(string $jwt): ?UnencryptedToken;

}
