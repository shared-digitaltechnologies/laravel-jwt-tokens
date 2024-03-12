<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Collection;

trait ClaimsBagHasRfc7643Helpers
{
    public function getRoles(): Collection
    {
        return $this->getCollection('roles');
    }

    public function hasRoles(): bool
    {
        return $this->has('roles');
    }

    public function withRoles(iterable $roles): static
    {
        return $this->withClaim('roles', iterator_to_array($roles, false));
    }

    public function setRoles(iterable $roles): static
    {
        return $this->set('roles', iterator_to_array($roles, false));
    }

    public function withoutRoles(): static
    {
        return $this->without('roles');
    }

    public function unsetRoles(): static
    {
        return $this->unset('roles');
    }

    public function addRole(string $role): static
    {
        return $this->add('roles', $role, unique: true);
    }

    public function withAddedRole(string $role): static
    {
        return $this->withAdded('roles', $role, unique: true);
    }

    public function removeRole(string $role): static
    {
        return $this->remove('roles', $role);
    }

    public function withRemovedRole(string $role): static
    {
        return $this->withRemoved('roles', $role);
    }

    public function containsRole(string $role): bool
    {
        return $this->contains('roles', $role);
    }

    public function getGroups(): Collection
    {
        return $this->getCollection('groups');
    }

    public function hasGroups(): bool
    {
        return $this->has('groups');
    }

    public function withGroups(iterable $groups): static
    {
        return $this->withClaim('groups', iterator_to_array($groups, false));
    }

    public function setGroups(iterable $groups): static
    {
        return $this->set('groups', iterator_to_array($groups, false));
    }

    public function withoutGroups(): static
    {
        return $this->without('groups');
    }

    public function unsetGroups(): static
    {
        return $this->unset('groups');
    }

    public function addGroup(string $group): static
    {
        return $this->add('groups', $group, unique: true);
    }

    public function withAddedGroup(string $group): static
    {
        return $this->withAdded('groups', $group, unique: true);
    }

    public function removeGroup(string $group): static
    {
        return $this->remove('groups', $group);
    }

    public function withRemovedGroup(string $group): static
    {
        return $this->withRemoved('groups', $group);
    }

    public function containsGroup(string $group): bool
    {
        return $this->contains('groups', $group);
    }

    public function getEntitlements(): Collection
    {
        return $this->getCollection('entitlements');
    }

    public function hasEntitlements(): bool
    {
        return $this->has('entitlements');
    }

    public function withEntitlements(iterable $entitlements): static
    {
        return $this->withClaim('entitlements', iterator_to_array($entitlements, false));
    }

    public function setEntitlements(iterable $entitlements): static
    {
        return $this->set('entitlements', iterator_to_array($entitlements, false));
    }

    public function withoutEntitlements(): static
    {
        return $this->without('entitlements');
    }

    public function unsetEntitlements(): static
    {
        return $this->unset('entitlements');
    }

    public function addEntitlement(string $entitlement): static
    {
        return $this->add('entitlements', $entitlement, unique: true);
    }

    public function withAddedEntitlement(string $entitlement): static
    {
        return $this->withAdded('entitlements', $entitlement, unique: true);
    }

    public function removeEntitlement(string $entitlement): static
    {
        return $this->remove('entitlements', $entitlement);
    }

    public function withRemovedEntitlement(string $entitlement): static
    {
        return $this->withRemoved('entitlements', $entitlement);
    }

    public function containsEntitlement(string $entitlement): bool
    {
        return $this->contains('entitlements', $entitlement);
    }
}
