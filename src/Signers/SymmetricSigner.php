<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Lcobucci\JWT\Signer\Key;

/**
 * Wraps a symmetric signing algorithm.
 */
class SymmetricSigner implements Signer, Verifier
{
    public function __construct(protected \Lcobucci\JWT\Signer $algorithm,
                                protected Key $key,
                                protected ?string $kid = null)
    {
    }

    public function sign(string $payload): string
    {
        return $this->algorithm->sign($payload, $this->key);
    }

    public function verify(string $expected, string $payload): bool
    {
        return $this->algorithm->verify($expected, $payload, $this->key);
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
