<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

readonly class SimpleKey implements VerificationKey, SigningKey
{
    public function __construct(public KeyType $keyType,
                                public string $contents,
                                public string $passphrase = '',
                                public ?string $kid = null)
    {
    }

    public static function rsa(string $contents, string $passphrase = '', ?string $kid = null): self
    {
        return new self(KeyType::RSA, $contents, $passphrase, $kid);
    }

    public function contents(): string
    {
        return $this->contents;
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }

    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    public function getKeyType(): KeyType
    {
        return $this->keyType;
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $this->keyType->isSupportedByAlgorithm($algorithm);
    }
}
