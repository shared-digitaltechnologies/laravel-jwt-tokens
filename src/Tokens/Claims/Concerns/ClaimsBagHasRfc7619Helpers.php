<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;

trait ClaimsBagHasRfc7619Helpers
{
    public function getIssuer(): ?string
    {
        return $this->get('iss');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireIssuer(): ?string
    {
        return $this->require('iss');
    }

    public function hasIssuer(): bool
    {
        return $this->has('iss');
    }

    public function withIssuer(string $iss): static
    {
        return $this->withClaim('iss', $iss);
    }

    public function setIssuer(string $iss): static
    {
        return $this->set('iss', $iss);
    }

    public function withoutIssuer(): static
    {
        return $this->without('iss');
    }

    public function unsetIssuer(): static
    {
        return $this->unset('iss');
    }

    public function getAudience(): ?string
    {
        return $this->getFirst('aud');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAudience(): string
    {
        return $this->requireFirst('aud');
    }

    public function hasAudience(): ?string
    {
        return $this->exists('aud');
    }

    public function withAudience(string $aud): ?string
    {
        return $this->withClaim('aud', $aud);
    }

    public function setAudience(string $aud): ?string
    {
        return $this->set('aud', $aud);
    }

    public function withoutAudience(): static
    {
        return $this->without('aud');
    }

    public function unsetAudience(): static
    {
        return $this->without('aud');
    }

    public function containsAudience(string $aud): bool
    {
        return $this->contains('aud', $aud);
    }

    public function addAudience(string $aud): static
    {
        return $this->add('aud', $aud, unique: true);
    }

    public function withAddedAudience(string $aud): static
    {
        return $this->withAdded('aud', $aud, unique: true);
    }

    public function removeAudience(string $aud): static
    {
        return $this->remove('aud', $aud);
    }

    public function getAudiences(): Collection
    {
        return $this->getCollection('aud');
    }

    public function hasAudiences(): bool
    {
        return $this->has('aud');
    }

    public function withAudiences(string|array $aud): static
    {
        return $this->withClaim('aud', $aud);
    }

    public function setAudiences(string|array $aud): static
    {
        return $this->set('aud', $aud);
    }

    public function withoutAudiences(): static
    {
        return $this->without('aud');
    }

    public function unsetAudiences(): static
    {
        return $this->unset('aud');
    }

    public function getSubject(): ?string
    {
        return $this->get('sub');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireSubject(): ?string
    {
        return $this->require('sub');
    }

    public function hasSubject(): bool
    {
        return $this->has('sub');
    }

    public function withSubject(string $sub): static
    {
        return $this->withClaim('sub', $sub);
    }

    public function setSubject(string $sub): static
    {
        return $this->set('sub', $sub);
    }

    public function withoutSubject(): static
    {
        return $this->without('sub');
    }

    public function unsetSubject(): static
    {
        return $this->unset('sub');
    }

    public function getExpiresAt(bool $milliseconds = false): ?Carbon
    {
        return $this->getTimestamp('exp', milliseconds: $milliseconds);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireExpiresAt(bool $milliseconds = false): Carbon
    {
        return $this->requireTimestamp('exp', milliseconds: $milliseconds);
    }

    public function hasExpiresAt(): bool
    {
        return $this->has('exp');
    }

    public function withExpiresAt(mixed $exp, bool $milliseconds = false): static
    {
        return $this->withTimestamp('exp', $exp, milliseconds: $milliseconds);
    }

    public function setExpiresAt(mixed $exp, bool $milliseconds = false): static
    {
        return $this->setTimestamp('exp', $exp, milliseconds: $milliseconds);
    }

    public function withoutExpiresAt(): static
    {
        return $this->without('exp');
    }

    public function unsetExpiresAt(): static
    {
        return $this->unset('exp');
    }

    public function getIssuedAt(bool $milliseconds = false): ?Carbon
    {
        return $this->getTimestamp('iat', milliseconds: $milliseconds);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireIssuedAt(bool $milliseconds = false): Carbon
    {
        return $this->requireTimestamp('iat', milliseconds: $milliseconds);
    }

    public function hasIssuedAt(): bool
    {
        return $this->has('iat');
    }

    public function withIssuedAt(mixed $iss, bool $milliseconds = false): static
    {
        return $this->withTimestamp('iat', $iss, milliseconds: $milliseconds);
    }

    public function setIssuedAt(mixed $iss, bool $milliseconds = false): static
    {
        return $this->setTimestamp('iat', $iss, milliseconds: $milliseconds);
    }

    public function withoutIssuedAt(): static
    {
        return $this->without('iat');
    }

    public function unsetIssuedAt(): static
    {
        return $this->unset('iat');
    }

    public function getNotBefore(bool $milliseconds = false): ?Carbon
    {
        return $this->getTimestamp('nbf', milliseconds: $milliseconds);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireNotBefore(bool $milliseconds = false): Carbon
    {
        return $this->requireTimestamp('nbf', milliseconds: $milliseconds);
    }

    public function hasNotBefore(): bool
    {
        return $this->has('nbf');
    }

    public function withNotBefore(mixed $nbf, bool $milliseconds = false): static
    {
        return $this->withTimestamp('nbf', $nbf, milliseconds: $milliseconds);
    }

    public function setNotBefore(mixed $nbf, bool $milliseconds = false): static
    {
        return $this->setTimestamp('nbf', $nbf, milliseconds: $milliseconds);
    }

    public function withoutNotBefore(): static
    {
        return $this->without('nbf');
    }

    public function unsetNotBefore(): static
    {
        return $this->unset('nbf');
    }

    public function getTokenId(): ?string
    {
        return $this->get('jti');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireTokenId(): ?string
    {
        return $this->require('jti');
    }

    public function hasTokenId(): bool
    {
        return $this->has('jti');
    }

    public function withTokenId(string $jti): static
    {
        return $this->withClaim('jti', $jti);
    }

    public function setTokenId(string $jti): static
    {
        return $this->set('jti', $jti);
    }

    public function withoutTokenId(): static
    {
        return $this->without('jti');
    }

    public function unsetTokenId(): static
    {
        return $this->unset('jti');
    }
}
