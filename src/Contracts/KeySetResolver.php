<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;

/**
 * Resolves key set descriptors into actual key sets.
 */
interface KeySetResolver
{
    /**
     * @param string $descriptor
     * @return KeySet
     * @throws KeySetLoadException
     */
    public function get(string $descriptor): KeySet;

    public function overwrite(string $descriptor, KeySet|VerificationKey|string $keySet): static;

    /**
     * @param string ...$descriptors
     * @return KeySet
     * @throws KeySetLoadException
     */
    public function combine(string ...$descriptors): KeySet;
}
