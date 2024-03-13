<?php

namespace Shrd\Laravel\JwtTokens\Guards\Concerns;

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Events\AuthenticatingByClaims;
use Shrd\Laravel\JwtTokens\Events\AuthenticatingByToken;
use Shrd\Laravel\JwtTokens\Events\AuthenticationByClaimsFailed;
use Shrd\Laravel\JwtTokens\Events\AuthenticatedByClaims;
use Shrd\Laravel\JwtTokens\Events\AuthenticationByTokenFailed;
use Shrd\Laravel\JwtTokens\Events\AuthenticatedByToken;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

trait HasTokenUserProvider
{
    use DispatchesEvents;

    private ClaimsUserProvider $provider;

    public function getProvider(): ClaimsUserProvider
    {
        return $this->provider;
    }

    public function setProvider(ClaimsUserProvider $provider): static
    {
        $this->provider = $provider;
        return $this;
    }

    protected function retrieveUserByClaims(ClaimsBag $claims): ?Authenticatable
    {
        $provider = $this->getProvider();
        $guard = $this->guardName();

        $this->dispatchEvent(new AuthenticatingByClaims(
            guard: $guard,
            claims: $claims
        ));

        $exception = null;
        $user = null;
        try {
            $user = $provider->retrieveByClaims($claims);
        } catch (Exception $e) {
            $exception = $e;
        }

        if($user === null) {
            $this->dispatchEvent(new AuthenticationByClaimsFailed(
                guard: $guard,
                claims: $claims,
                exception: $exception
            ));
            return null;
        }

        $this->dispatchEvent(new AuthenticatedByClaims(
            guard: $guard,
            user: $user,
            claims: $claims
        ));
        return $user;
    }

    protected function retrieveUserByToken(Token $token): ?Authenticatable
    {
        $provider = $this->getProvider();
        $guard = $this->guardName();

        $this->dispatchEvent(new AuthenticatingByToken(
            guard: $guard,
            token: $token
        ));

        $exception = null;
        $user = null;
        try {
            $user = $provider->retrieveByJwtToken($token);
        } catch (Exception $e) {
            $exception = $e;
        }

        if($user === null) {
            $this->dispatchEvent(new AuthenticationByTokenFailed(
                guard: $guard,
                token: $token,
                exception: $exception
            ));
            return null;
        }

        $this->dispatchEvent(new AuthenticatedByToken(
            guard: $guard,
            user: $user,
            token: $token
        ));
        return $user;
    }
}
