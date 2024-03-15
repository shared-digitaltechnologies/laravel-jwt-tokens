<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

readonly class HasHeaderWithValueIn extends WithValueInConstraint
{
    public function __construct(string $header, iterable $values)
    {
        parent::__construct($header, $values, 'headers');
    }

    protected function getTargetDataSet(UnencryptedToken $token): Token\DataSet
    {
        return $token->headers();
    }
}
