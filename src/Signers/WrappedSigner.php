<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Lcobucci\JWT\Signer\Key;

/**
 * Wraps an asymmetric signing algorithm
 */
readonly class WrappedSigner implements Signer
{

    public function __construct(public \Lcobucci\JWT\Signer $algorithm,
                                public Key $key,
                                public ?string $kid = null)
    {
    }

    public function sign(string $payload): string
    {
        return $this->algorithm->sign($payload, $this->key);
    }


    public function algorithmId(): string
    {
        return $this->algorithm->algorithmId();
    }

    public function keyId(): ?string
    {
        if($this->kid !== null) return $this->kid;
        if(method_exists($this->key, 'getKeyId')) {
            return $this->key->getKeyId();
        }
        return null;
    }
}
