<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;

trait ClaimsBagHasAzureHelpers
{
    public static string $tenantIdClaimName = 'tid';

    public function getTenantId(): ?string
    {
        return $this->get(static::$tenantIdClaimName);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireTenantId(): ?string
    {
        return $this->require(static::$tenantIdClaimName);
    }

    public function hasTenantId(): bool
    {
        return $this->has(static::$tenantIdClaimName);
    }

    public function withTenantId(string $tid): static
    {
        return $this->withClaim(static::$tenantIdClaimName, $tid);
    }

    public function setTenantId(string $tid): static
    {
        return $this->set(static::$tenantIdClaimName, $tid);
    }

    public function withoutTenantId(): static
    {
        return $this->without(static::$tenantIdClaimName);
    }

    public function unsetTenantId(): static
    {
        return $this->unset(static::$tenantIdClaimName);
    }

    public static string $identityProviderClaimName = 'idp';

    public function getIdentityProvider(): mixed
    {
        return $this->get(static::$identityProviderClaimName);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireIdentityProvider(): ?string
    {
        return $this->require(static::$identityProviderClaimName);
    }

    public function hasIdentityProvider(): bool
    {
        return $this->has(static::$identityProviderClaimName);
    }

    public function withIdentityProvider(mixed $idp): static
    {
        return $this->withClaim(static::$identityProviderClaimName, $idp);
    }

    public function setIdentityProvider(mixed $idp): static
    {
        return $this->set(static::$identityProviderClaimName, $idp);
    }

    public function withoutIdentityProvider(): static
    {
        return $this->without(static::$identityProviderClaimName);
    }

    public function unsetIdentityProvider(): static
    {
        return $this->unset(static::$identityProviderClaimName);
    }

    public static string $trustFrameworkPolicy = 'tfp';

    public function getTrustFrameworkPolicy(): ?string
    {
        return $this->get(static::$trustFrameworkPolicy);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireTrustFrameworkPolicy(): ?string
    {
        return $this->require(static::$trustFrameworkPolicy);
    }

    public function hasTrustFrameworkPolicy(): bool
    {
        return $this->has(static::$trustFrameworkPolicy);
    }

    public function withTrustFrameworkPolicy(string $tfp): static
    {
        return $this->withClaim(static::$trustFrameworkPolicy, $tfp);
    }

    public function setTrustFrameworkPolicy(string $tfp): static
    {
        return $this->set(static::$trustFrameworkPolicy, $tfp);
    }

    public function withoutTrustFrameworkPolicy(): static
    {
        return $this->without(static::$trustFrameworkPolicy);
    }

    public function unsetTrustFrameworkPolicy(): static
    {
        return $this->unset(static::$trustFrameworkPolicy);
    }
}
