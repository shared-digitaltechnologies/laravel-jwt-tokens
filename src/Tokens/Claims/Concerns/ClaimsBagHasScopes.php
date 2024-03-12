<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Collection;

trait ClaimsBagHasScopes
{
    /**
     * Returns the scopes of this claims bag.
     *
     * @return Collection<int, string>
     */
    public function getScopes(): Collection
    {
        $scp = $this->get('scp');
        if($scp === null || $scp === '') return Collection::make();
        return Collection::make(explode(' ', $scp));
    }

    public function withScopes(string|iterable $scopes): static
    {
        if(is_iterable($scopes)) $scopes = implode(' ', iterator_to_array($scopes));
        return $this->withClaim('scp', $scopes);
    }

    public function setScopes(string|iterable $scopes): static
    {
        if(is_iterable($scopes)) $scopes = implode(' ', iterator_to_array($scopes));
        return $this->set('scp', $scopes);
    }

    public function withoutScopes(): static
    {
        return $this->without('scp');
    }

    public function unsetScopes(): static
    {
        return $this->unset('scp');
    }

    /**
     * Returns whether this claims bag has a `scp` claim.
     *
     * @return bool
     */
    public function hasScopes(): bool
    {
        return $this->has('scp');
    }

    /**
     * Returns whether this claims bag has all the provided scopes.
     *
     * @param string|iterable $scopes
     * @return bool
     */
    public function containsScopes(string|iterable $scopes): bool
    {
        if(is_string($scopes)) $scopes = explode(' ', trim($scopes));
        $claimScopes = $this->getScopes();
        foreach ($scopes as $scope) {
            if(!$claimScopes->contains($scope)) return false;
        }
        return true;
    }

    /**
     * Returns whether this claims bag has at least one of the provided scopes.
     *
     * @param string|iterable $scopes
     * @return bool
     */
    public function containsAnyScope(string|iterable $scopes): bool
    {
        if(is_string($scopes)) $scopes = explode(' ', trim($scopes));
        $claimScopes = $this->getScopes();
        foreach ($scopes as $scope) {
            if($claimScopes->contains($scope)) return true;
        }
        return false;
    }

    /**
     * Adds the provided scope to the claims bag.
     *
     * @param string|iterable $scopes
     * @return static
     */
    public function withAddedScopes(string|iterable $scopes): static
    {
        $result = clone $this;
        return $result->setScopes($scopes);
    }

    public function addScopes(string|iterable $scopes): static
    {
        if(is_string($scopes)) {
            $scopes = explode(' ', trim($scopes));
        }

        $newScopes = $this->getScopes();
        foreach ($scopes as $scope) {
            if(!$newScopes->contains($scope)) {
                $newScopes[] = $scope;
            }
        }

        return $this->setScopes($newScopes);
    }

    public function removeScopes(string|iterable $scopes): static
    {
        if(is_string($scopes)) {
            $scopes = explode(' ', trim($scopes));
        } else {
            $scopes = iterator_to_array($scopes);
        }

        $newScopes = $this->getScopes()->filter(fn($s) => in_array($s, $scopes));

        return $this->setScopes($newScopes);
    }

    public function withRemovedScopes(string|iterable $scopes): static
    {
        $result = clone $this;
        return $result->removeScopes($scopes);
    }
}
