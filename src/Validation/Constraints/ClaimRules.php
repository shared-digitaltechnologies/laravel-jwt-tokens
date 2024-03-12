<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;

readonly class ClaimRules extends RulesConstraint
{

    protected function errorRef(): string
    {
        return 'claims';
    }

    protected function data(Token $token): array
    {
        if(! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation("Pass an unencrypted token.", static::class);
        }

        return $token->claims()->all();
    }
}
