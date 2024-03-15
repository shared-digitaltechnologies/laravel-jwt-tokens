<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use BackedEnum;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;

readonly abstract class WithValueInConstraint implements Constraint
{
    protected array $values;

    public function __construct(protected string $key, iterable $values, protected string $tokenSection)
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

    protected abstract function getTargetDataSet(UnencryptedToken $token): Token\DataSet;

    /**
     * @throws WithValueInConstraintViolation
     * @throws MissingMandatoryValuesViolation
     */
    public function assert(Token $token): void
    {
        if(!($token instanceof UnencryptedToken)) {
            throw \Lcobucci\JWT\Validation\ConstraintViolation::error('You should pass an unencrypted token', $this);
        }

        $dataSet = $this->getTargetDataSet($token);

        if(!$dataSet->has($this->key)) {
            throw new MissingMandatoryValuesViolation(
                constraint: static::class,
                tokenSection: $this->tokenSection,
                missing: [$this->key]
            );
        }

        if(!in_array($this->values, $dataSet->get($this->key))) {
            throw new WithValueInConstraintViolation(
                constraint: static::class,
                key: $this->key,
                tokenSection: $this->tokenSection,
                allowedValues: $this->values,
            );
        }
    }
}
