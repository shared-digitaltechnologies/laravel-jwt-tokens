<?php

namespace Shrd\Laravel\JwtTokens\Testing\Extensions;

use Illuminate\Contracts\Support\Arrayable;
use Lcobucci\JWT\UnencryptedToken;
use RuntimeException;
use Shrd\Laravel\JwtTokens\Guards\GuardWithTokenLoader;
use Shrd\Laravel\JwtTokens\Loaders\TestTokenLoader;
use Shrd\Laravel\JwtTokens\Tokens\Token;

trait CreatesTestTokens
{

    public function usingTestTokenLoader(?string $guard = null): TestTokenLoader
    {
        $authManager = $this->app->make('auth');
        $guard = $authManager->guard($guard);
        if(!($guard instanceof GuardWithTokenLoader)) {
            throw new RuntimeException(get_class($guard),' does not implement '.GuardWithTokenLoader::class);
        }

        $loader = $guard->getTokenLoader();
        if($loader instanceof TestTokenLoader) {
            return $loader;
        }

        $testLoader = new TestTokenLoader;
        $guard->setTokenLoader($testLoader);
        return $testLoader;
    }

    public function usingTestToken(array|Arrayable $headers = [],
                                   array|Arrayable $claims = [],
                                   ?string $signature = null,
                                   mixed $expiresIn = '2 hours',
                                   ?string $guard = null): Token
    {
        return $this->usingTestTokenLoader($guard)->newTestToken(
            headers: $headers,
            claims: $claims,
            signature: $signature,
            expiresIn: $expiresIn
        );
    }

    public function allowTestToken(UnencryptedToken $token,
                                   ?string $jwt = null,
                                   ?string $guard = null): static
    {
        $this->usingTestTokenLoader($guard)->allowToken($token, $jwt);
        return $this;
    }

    public function revokeTestToken(UnencryptedToken|string $token, ?string $guard = null): static
    {
        $this->usingTestTokenLoader($guard)->revokeToken($token);
        return $this;
    }

    public function revokeAllTestTokens(?string $guard = null): static
    {
        $this->usingTestTokenLoader($guard)->revokeAllTokens();
        return $this;
    }
}
