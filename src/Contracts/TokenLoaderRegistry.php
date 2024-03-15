<?php

namespace Shrd\Laravel\JwtTokens\Contracts;

use IteratorAggregate;

/**
 * @extends IteratorAggregate<string, TokenLoader>
 */
interface TokenLoaderRegistry extends IteratorAggregate
{
    public function register(string $name, string|callable|TokenLoader $loader): static;

    public function defaultLoader(): string;

    public function setDefaultLoader(string $name): static;

    public function has(?string $name): bool;

    public function get(?string $name = null): TokenLoader;

    /**
     * Gives names of the registered loaders.
     *
     * @return string[]
     */
    public function names(): array;

}
