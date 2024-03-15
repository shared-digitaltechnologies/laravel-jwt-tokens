<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

readonly class HasClaimWithValueIn extends WithValueInConstraint
{
    public function __construct(string $claim, iterable $values)
    {
        parent::__construct($claim, $values, 'claims');
    }

    protected function getTargetDataSet(UnencryptedToken $token): Token\DataSet
    {
        return $token->claims();
    }
}
