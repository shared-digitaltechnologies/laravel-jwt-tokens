<?php

namespace Shrd\Laravel\JwtTokens\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Exceptions\InvalidJwtException;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

class JwtTokenGuard implements Guard, GuardWithTokenLoader
{
    use Macroable;

    private ?Authenticatable $user = null;

    private ?UnencryptedToken $token = null;

    private ?ClaimsBag $claims = null;

    public function __construct(public readonly string                    $name,
                                protected TokenLoader                     $loader,
                                protected ClaimsUserProvider|UserProvider $provider,
                                protected ?Request                        $request = null)
    {
        if($request) $this->setRequest($request);
    }

    public function getProvider(): ClaimsUserProvider|UserProvider
    {
        return $this->provider;
    }

    public function setProvider(ClaimsUserProvider|UserProvider $provider): static
    {
        $this->provider = $provider;
        return $this;
    }

    public function getRequest(): Request
    {
        if($this->request === null) {
            $this->request = Request::createFromGlobals();
        }
        return $this->request;
    }

    public function setRequest(?Request $request): static
    {
        $this->request = $request;
        $this->token = null;
        return $this;
    }

    public function getTokenLoader(): TokenLoader
    {
        return $this->loader;
    }

    public function setTokenLoader(TokenLoader $loader): static
    {
        $this->loader = $loader;
        return $this;
    }

    public function guardName(): string
    {
        return $this->name;
    }

    /**
     * @throws InvalidJwtException
     */
    public function token(): ?UnencryptedToken
    {
        if($this->token !== null) return $this->token;

        $jwt = $this->getRequest()->bearerToken();
        if($jwt === null) return null;

        $this->token = $this->loader->load($jwt);
        return $this->token;
    }

    /**
     * @throws JwtParseException
     */
    public function setToken(null|string|UnencryptedToken $token): static
    {
        if(is_string($token)) {
            $token = $this->loader->parse($token);
        }
        $this->token = $token;
        return $this;
    }

    public function hasToken(): bool
    {
        return $this->token !== null;
    }

    public function forgetUser(): static
    {
        return $this->setUser(null);
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    public function setUser(?Authenticatable $user): static
    {
        $this->user = $user;
        return $this;
    }

    public function setClaims(mixed $claims): static
    {
        $this->claims = ClaimsBag::from($claims);
        return $this->forgetUser();
    }

    /**
     * @throws InvalidJwtException
     */
    public function claims(): ClaimsBag
    {
        if($this->claims !== null) {
            return $this->claims;
        }

        $token = $this->token();
        if($token !== null) {
            return ClaimsBag::fromUnencryptedToken($token);
        } else {
            return ClaimsBag::empty();
        }
    }

    protected function retrieveUserByClaims(ClaimsBag $claims): ?Authenticatable
    {
        $provider = $this->getProvider();

        if($provider instanceof ClaimsUserProvider) {
            return $provider->retrieveByClaims($claims);
        }

        return $provider->retrieveById($claims->getSubject());
    }

    /**
     * @throws InvalidJwtException
     */
    public function user(): ?Authenticatable
    {
        if($this->user !== null) return $this->user;

        if($this->claims !== null) {
            $user = $this->retrieveUserByClaims($this->claims);
            $this->setUser($user);
            return $user;
        }

        $token = $this->token();
        if($token === null) {
            $this->forgetUser();
            return null;
        }

        $user = $this->retrieveUserByClaims($this->claims());
        $this->setUser($user);
        return $user;
    }

    /**
     * @throws InvalidJwtException
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * @throws InvalidJwtException
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * @throws AuthenticationException
     * @throws InvalidJwtException
     */
    public function authenticate(): Authenticatable
    {
        return $this->user() ?? throw new AuthenticationException;
    }

    public function validate(array $credentials = []): bool
    {
        if($this->provider instanceof UserProvider) {
            $user = $this->provider->retrieveByCredentials($credentials);
            if($user === null) return false;

            return $this->provider->validateCredentials($user, $credentials);
        } else {
            return false;
        }
    }

    /**
     * @throws InvalidJwtException
     */
    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

}
