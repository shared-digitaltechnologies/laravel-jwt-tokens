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
     * Gets the keyset from the provided descriptor.
     *
     * @param string $descriptor
     * @return KeySet
     * @throws KeySetLoadException
     */
    public function get(string $descriptor): KeySet;

    /**
     * Combines multiple key sets into one key set using the provided descriptors.
     *
     * @param string ...$descriptors
     * @return KeySet
     * @throws KeySetLoadException
     */
    public function combine(string ...$descriptors): KeySet;

    /**
     * Overwrites the key set that will be returned by the provided descriptor.
     *
     * @param string $descriptor
     * @param KeySet|VerificationKey|string $keySet
     * @return $this
     */
    public function overwrite(string $descriptor, KeySet|VerificationKey|string $keySet): static;

    /**
     * Returns the key set that can be used to check if a token was issued by the provided issuer.
     *
     * @param IssuesTokens $issuer
     * @return KeySet
     * @throws KeySetLoadException
     */
    public function forTokenIssuer(IssuesTokens $issuer): KeySet;


}
