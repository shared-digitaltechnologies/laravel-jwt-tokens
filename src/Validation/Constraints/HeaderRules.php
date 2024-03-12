<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;

readonly class HeaderRules extends RulesConstraint
{

    protected function errorRef(): string
    {
        return 'headers';
    }

    protected function data(Token $token): array
    {
        return $token->headers()->all();
    }
}
