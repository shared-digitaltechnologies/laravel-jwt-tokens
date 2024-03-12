<?php

namespace Shrd\Laravel\JwtTokens\UserProviders;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\BindingResolutionException;
use InvalidArgumentException;
use Shrd\Laravel\JwtTokens\Contracts\TokenUserProvider;
use Shrd\Laravel\JwtTokens\Contracts\TokenUserProviderFactory;

class DefaultTokenUserProviderFactory implements TokenUserProviderFactory
{
    protected mixed $authManager;

    /**
     * @throws BindingResolutionException
     */
    public function __construct(Container $container)
    {
        $this->authManager = $container->make('auth');
    }

    public function createTokenUserProvider(?string $provider = null): TokenUserProvider
    {
        $provider = $this->authManager->createUserProvider($provider);
        if(!($provider instanceof TokenUserProvider)) {
            throw new InvalidArgumentException(
                "The user-provider '$provider' is not a ".TokenUserProvider::class
            );
        }
        return $provider;
    }
}
