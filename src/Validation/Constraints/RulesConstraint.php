<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;

readonly abstract class RulesConstraint implements Constraint
{
    public function __construct(protected ValidationFactory $validationFactory,
                                protected array $rules,
                                protected array $messages,
                                protected array $attributes)
    {
    }

    abstract protected function errorRef(): string;

    abstract protected function data(Token $token): array;

    /**
     * @throws ValidationConstraintViolation
     */
    public function assert(Token $token): void
    {
        $data = $this->data($token);

        $validator = $this->validationFactory->make(
            $data,
            $this->rules,
            $this->messages,
            $this->attributes
        );

        if($validator->fails()) {
            throw new ValidationConstraintViolation(static::class, $validator);
        }
    }
}
