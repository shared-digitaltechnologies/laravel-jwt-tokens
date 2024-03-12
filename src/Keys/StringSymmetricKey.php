<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

class StringSymmetricKey implements SymmetricKey
{

    public function __construct(protected string $contents, protected ?string $kid = null)
    {
    }

    public function contents(): string
    {
        return $this->contents;
    }

    public function passphrase(): string
    {
        return '';
    }

    public function getKeyType(): KeyType
    {
        return KeyType::OCT;
    }

    public function getKeyBitsLength(): int
    {
        return 8 * strlen($this->contents);
    }

    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $this->getKeyType()->isSupportedByAlgorithm($algorithm)
            && $this->getKeyBitsLength() >= $algorithm->minimumBitsLengthForKey();
    }
}
