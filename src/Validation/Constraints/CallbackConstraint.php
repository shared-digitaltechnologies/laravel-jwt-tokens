<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Closure;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Throwable;

readonly class CallbackConstraint implements Constraint
{

    protected Closure $callback;

    public function __construct(callable $callback, protected ?string $message = null)
    {
        $this->callback = $callback(...);
    }

    public function assert(Token $token): void
    {
        $callback = $this->callback;

        try {
            $result = $callback($token);
        } catch (Throwable $exception) {
            throw new ConstraintViolation(
                $this->message ?? "Callback failed with exception ".$exception::class.": ".$exception->getMessage(),
                static::class
            );
        }

        if($result === null || $result === true || $result instanceof Token) return;
        if($result === false) throw new ConstraintViolation($this->message ?? "Callback returned false.", static::class);
        throw new ConstraintViolation($this->message ?? strval($result), static::class);
    }
}
