<?php

namespace Shrd\Laravel\JwtTokens\Signers;


use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Lcobucci\JWT\Signer\Key;

readonly class AsymmetricSigner implements Signer, Verifier
{
    public function __construct(public AlgorithmImplementation $algorithm,
                                public Key $privateKey,
                                public Key $publicKey,
                                public ?string $kid = null)
    {
    }

    public function sign(string $payload): string
    {
        return $this->algorithm->sign($payload, $this->privateKey);
    }

    public function algorithmId(): string
    {
        return $this->algorithm->algorithmId();
    }

    public function keyId(): ?string
    {
        if($this->kid !== null) return $this->kid;

        if(method_exists($this->privateKey, 'getKeyId')) {
            return $this->privateKey->getKeyId();
        }

        if(method_exists($this->publicKey, 'getKeyId')) {
            return $this->publicKey->getKeyId();
        }

        return null;
    }

    public function verify(string $expected, string $payload): bool
    {
        return $this->algorithm->verify($expected, $payload, $this->publicKey);
    }
}
