<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

readonly class NoneKey implements VerificationKey
{

    public function __construct(protected ?string $kid = null)
    {
    }

    public function contents(): string
    {
        return '';
    }

    public function passphrase(): string
    {
        return '';
    }

    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $algorithm === Algorithm::NONE;
    }
}
