<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use Illuminate\Contracts\Container\Container;

/**
 * Factory that creates key set loaders.
 */
interface KeySetLoaderFactory extends KeySetLoader
{
    /**
     * Adds a new key set loader that will be called when the descriptor starts with the provided prefix.
     *
     * @param string $prefix
     * @param callable(Container $app, KeySetLoader $defaultLoader): KeySetLoader $callback
     * @return $this
     */
    public function extend(string $prefix, callable $callback): static;

    /**
     * Returns an instance of a key set loader that can be used to load the provided key set descriptor.
     *
     * @param string $descriptor
     * @return KeySetLoader
     */
    public function loaderFor(string $descriptor): KeySetLoader;
}
