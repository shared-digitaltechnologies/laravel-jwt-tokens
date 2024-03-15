<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use BackedEnum;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;

readonly class ClaimValuesIn implements Constraint
{
    protected array $values;

    public function __construct(protected string $claim, iterable $values)
    {
        $normalizedValues = [];

        foreach ($values as $value) {
            if($value instanceof BackedEnum) {
                $normalizedValues[] = $value->value;
            } else {
                $normalizedValues[] = $value;
            }
        }

        $this->values = $normalizedValues;
    }

    /**
     * @throws WithValueInConstraintViolation
     */
    public function assert(Token $token): void
    {
        if(!($token instanceof UnencryptedToken)) {
            throw \Lcobucci\JWT\Validation\ConstraintViolation::error('You should pass an unencrypted token', $this);
        }

        $claims = $token->claims();

        $claimValues = $claims->get($this->claim);

        if($claimValues === null) return;
        if(!is_array($claimValues)) $claimValues = [$claimValues];

        foreach ($claimValues as $claimValue) {
            if(!in_array($this->values, $claimValue)) {
                throw new WithValueInConstraintViolation(
                    constraint: static::class,
                    key: $this->claim,
                    tokenSection: 'claims',
                    allowedValues: $this->values,
                );
            }
        }
    }
}
