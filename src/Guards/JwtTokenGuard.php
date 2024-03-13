<?php

namespace Shrd\Laravel\JwtTokens\Guards;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use Lcobucci\JWT\Parser as TokenParser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Shrd\Laravel\JwtTokens\Contracts\ClaimsUserProvider;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Guards\Concerns\HasParser;
use Shrd\Laravel\JwtTokens\Guards\Concerns\HasRequest;
use Shrd\Laravel\JwtTokens\Guards\Concerns\HasTokenUserProvider;
use Shrd\Laravel\JwtTokens\Tokens\Claims\ClaimsBag;

class JwtTokenGuard
{
    use Macroable,
        HasParser,
        HasTokenUserProvider,
        HasRequest;

    private ?Authenticatable $user = null;
    private bool $userResolved = false;

    private ?Token $token = null;
    private ?ClaimsBag $claims = null;

    public function __construct(public readonly string $name,
                                TokenParser            $parser,
                                ClaimsUserProvider     $provider,
                                ?Request               $request = null)
    {
        $this
            ->setParser($parser)
            ->setProvider($provider);

        if($request) $this->setRequest($request);
    }

    public function guardName(): string
    {
        return $this->name;
    }

    public function setRequest(?Request $request): static
    {
        $this->request = $request;
        $this->token = null;
        return $this;
    }

    /**
     * @throws JwtParseException
     */
    public function token(): ?Token
    {
        if($this->token !== null) return $this->token;

        $jwt = $this->getRequest()->bearerToken();
        if($jwt === null) return null;

        $this->token = $this->parse($jwt);
        return $this->token;
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
        $this->userResolved = true;
        return $this;
    }

    public function setClaims(mixed $claims): static
    {
        $this->claims = ClaimsBag::from($claims);
        $this->user = null;
        $this->userResolved = false;
        return $this;
    }

    /**
     * @throws JwtParseException
     */
    public function claims(): ClaimsBag
    {
        if($this->claims !== null) {
            return $this->claims;
        }


        $token = $this->token();
        if($token instanceof \Shrd\Laravel\JwtTokens\Tokens\Token) {
            return $token->claims;
        } else if($token instanceof UnencryptedToken) {
            return ClaimsBag::fromDataSet($token->claims());
        } else {
            return ClaimsBag::empty();
        }
    }

    /**
     * @throws JwtParseException
     */
    public function user(): ?Authenticatable
    {
        if($this->userResolved) return $this->user;

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

        $user = $this->retrieveUserByToken($token);
        $this->setUser($user);
        return $user;
    }

    /**
     * @throws JwtParseException
     */
    public function guest(): bool
    {
        return !$this->check();
    }

    /**
     * @throws JwtParseException
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * @throws AuthenticationException
     * @throws JwtParseException
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
     * @throws JwtParseException
     */
    public function id(): ?int
    {
        return $this->user()?->getAuthIdentifier();
    }

}
