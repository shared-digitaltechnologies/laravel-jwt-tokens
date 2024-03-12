<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Exceptions\UnsupportedAlgorithmException;

readonly class SignedUsing implements Constraint
{
    /**
     * @param Algorithm[] $algorithms
     */
    public function __construct(protected array $algorithms = [])
    {
    }

    protected function getAllowedAlgorithmsString(): string
    {
        return implode(', ', $this->algorithms);
    }

    public function assert(Token $token): void
    {
        $alg = $token->headers()->get('alg');
        if($alg === null) {
            throw new ConstraintViolation("Token has no `alg` header.", static::class);
        }

        try {
            $algorithm = Algorithm::fromAlgorithmId($alg);
        } catch (UnsupportedAlgorithmException) {
            throw new ConstraintViolation("Algorithm '$alg' not supported.", static::class);
        }

        if(!in_array($algorithm, $this->algorithms)) {
            throw new ConstraintViolation(
                "Algorithm '$alg' not one of allowed algorithms: ".$this->getAllowedAlgorithmsString(),
                static::class
            );
        }
    }
}
