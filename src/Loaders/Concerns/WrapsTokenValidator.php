<?php

namespace Shrd\Laravel\JwtTokens\Loaders\Concerns;

use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;
use Shrd\Laravel\JwtTokens\DateTime\DateRange;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;

trait WrapsTokenValidator
{
    public abstract function validator(): TokenValidator;


    /**
     * @param string $jwt
     * @return Token
     * @throws JwtParseException
     */
    public abstract function parse(string $jwt): Token;

    /**
     * @param string $jwt
     * @return Token|null
     */
    public abstract function tryParse(string $jwt): ?Token;


    public function check(string|Token $token): bool
    {
        if(is_string($token)) {
            $token = $this->tryParse($token);
            if($token === null) return false;
        }

        return $this->validator()->check($token);
    }

    public function violations(Token $token): array
    {
        return $this->validator()->violations($token);
    }

    /**
     * @throws InvalidJwtException
     */
    public function validate(string|Token $token): Token
    {
        if(is_string($token)) {
            $token = $this->parse($token);
        }

        return $this->validator()->validate($token);
    }

    public function validDateRange(string|Token $token): DateRange
    {
        if(is_string($token)) {
            $token = $this->tryParse($token);
            if($token === null) return DateRange::empty();
        }

        return $this->validator()->validDateRange($token);
    }
}
