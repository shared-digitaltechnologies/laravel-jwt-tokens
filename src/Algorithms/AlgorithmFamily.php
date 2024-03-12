<?php

namespace Shrd\Laravel\JwtTokens\Algorithms;

use Generator;
use Shrd\Laravel\JwtTokens\Keys\KeyType;

enum AlgorithmFamily
{
    case RSAPKCS1;
    case RSAPPS;
    case ECDSA;
    case EdDSA;
    case HMAC;
    case BLAKE;
    case NONE;

    public function isSymmetric(): bool
    {
        return match ($this) {
            self::HMAC, self::BLAKE, self::NONE => true,
            default => false,
        };
    }

    public function isAsymmetric(): bool
    {
        return !$this->isSymmetric();
    }

    public function getKeyType(): KeyType
    {
        return match ($this) {
            self::RSAPKCS1, self::RSAPPS => KeyType::RSA,
            self::ECDSA => KeyType::EC,
            self::EdDSA => KeyType::OKP,
            self::HMAC, self::BLAKE => KeyType::OCT,
            self::NONE => KeyType::NONE
        };
    }

    /**
     * @return Generator<void, int, Algorithm, void>
     */
    public function algorithms(): Generator
    {
        foreach (Algorithm::cases() as $algorithm) {
            if($algorithm->getAlgorithmFamily() === $this) {
                yield $algorithm;
            }
        }
    }
}
