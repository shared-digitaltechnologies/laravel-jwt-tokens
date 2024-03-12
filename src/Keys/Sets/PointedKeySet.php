<?php

namespace Shrd\Laravel\JwtTokens\Keys\Sets;

use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

/**
 * @template T of VerificationKey
 * @extends KeySet<T>
 */
interface PointedKeySet extends KeySet
{
    /**
     * @return VerificationKey&T
     */
    public function getKey(): VerificationKey;

    public function getKeyId(): ?string;
}
