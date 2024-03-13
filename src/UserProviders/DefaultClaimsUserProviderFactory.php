<?php

namespace Shrd\Laravel\JwtTokens\UserProviders;

use Illuminate\Container\Container;
use Illuminate\Contracts\Container\BindingResolutionException;
use InvalidArgumentException;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProviderFactory;

class DefaultClaimsUserProviderFactory implements ClaimsUserProviderFactory
{
    protected mixed $authManager;

    /**
     * @throws BindingResolutionException
     */
    public function __construct(Container $container)
    {
        $this->authManager = $container->make('auth');
    }

    public function createClaimsUserProvider(?string $provider = null): ClaimsUserProvider
    {
        $provider = $this->authManager->createUserProvider($provider);
        if(!($provider instanceof ClaimsUserProvider)) {
            throw new InvalidArgumentException(
                "The user-provider '$provider' is not a ".ClaimsUserProvider::class
            );
        }
        return $provider;
    }
}
