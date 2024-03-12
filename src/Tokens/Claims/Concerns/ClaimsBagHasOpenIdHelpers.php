<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;

/**
 * See the [OpenID Connect Spec](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) for more
 * information.
 */
trait ClaimsBagHasOpenIdHelpers
{
    public function getName(): ?string
    {
        return $this->get('name');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireName(): string
    {
        return $this->require('name');
    }

    public function hasName(): bool
    {
        return $this->has('name');
    }

    public function withName(string $name): static
    {
        return $this->withClaim('name', $name);
    }

    public function setName(string $name): static
    {
        return $this->set('name', $name);
    }

    public function withoutName(): static
    {
        return $this->without('name');
    }

    public function unsetName(): static
    {
        return $this->unset('name');
    }

    public function getGivenName(): ?string
    {
        return $this->get('given_name');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireGivenName(): string
    {
        return $this->require('given_name');
    }

    public function hasGivenName(): bool
    {
        return $this->has('given_name');
    }

    public function withGivenName(string $name): static
    {
        return $this->withClaim('given_name', $name);
    }

    public function setGivenName(string $name): static
    {
        return $this->set('given_name', $name);
    }

    public function withoutGivenName(): static
    {
        return $this->without('given_name');
    }

    public function unsetGivenName(): static
    {
        return $this->unset('given_name');
    }

    public function getFamilyName(): ?string
    {
        return $this->get('family_name');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireFamilyName(): string
    {
        return $this->require('family_name');
    }

    public function hasFamilyName(): bool
    {
        return $this->has('family_name');
    }

    public function withFamilyName(string $name): static
    {
        return $this->withClaim('family_name', $name);
    }

    public function setFamilyName(string $name): static
    {
        return $this->set('family_name', $name);
    }

    public function withoutFamilyName(): static
    {
        return $this->without('family_name');
    }

    public function unsetFamilyName(): static
    {
        return $this->unset('family_name');
    }

    public function getMiddleName(): ?string
    {
        return $this->get('middle_name');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireMiddleName(): string
    {
        return $this->require('middle_name');
    }

    public function hasMiddleName(): bool
    {
        return $this->has('middle_name');
    }

    public function withMiddleName(string $name): static
    {
        return $this->withClaim('middle_name', $name);
    }

    public function setMiddleName(string $name): static
    {
        return $this->set('middle_name', $name);
    }

    public function withoutMiddleName(): static
    {
        return $this->without('middle_name');
    }

    public function unsetMiddleName(): static
    {
        return $this->unset('middle_name');
    }

    public function getNickname(): ?string
    {
        return $this->get('nickname');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireNickname(): string
    {
        return $this->require('nickname');
    }

    public function hasNickname(): bool
    {
        return $this->has('nickname');
    }

    public function withNickname(string $name): static
    {
        return $this->withClaim('nickname', $name);
    }

    public function setNickname(string $name): static
    {
        return $this->set('nickname', $name);
    }

    public function withoutNickname(): static
    {
        return $this->without('nickname');
    }

    public function unsetNickname(): static
    {
        return $this->unset('nickname');
    }

    public function getPreferredUsername(): ?string
    {
        return $this->get('preferred_username');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requirePreferredUsername(): string
    {
        return $this->require('preferred_username');
    }

    public function hasPreferredUsername(): bool
    {
        return $this->has('preferred_username');
    }

    public function withPreferredUsername(string $name): static
    {
        return $this->withClaim('preferred_username', $name);
    }

    public function setPreferredUsername(string $name): static
    {
        return $this->set('preferred_username', $name);
    }

    public function withoutPreferredUsername(): static
    {
        return $this->without('preferred_username');
    }

    public function unsetPreferredUsername(): static
    {
        return $this->unset('preferred_username');
    }

    public function getProfile(): ?string
    {
        return $this->get('profile');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireProfile(): string
    {
        return $this->require('profile');
    }

    public function hasProfile(): bool
    {
        return $this->has('profile');
    }

    public function withProfile(string $url): static
    {
        return $this->withClaim('profile', $url);
    }

    public function setProfile(string $url): static
    {
        return $this->set('profile', $url);
    }

    public function withoutProfile(): static
    {
        return $this->without('profile');
    }

    public function unsetProfile(): static
    {
        return $this->unset('profile');
    }

    public function getPicture(): ?string
    {
        return $this->get('picture');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requirePicture(): string
    {
        return $this->require('picture');
    }

    public function hasPicture(): bool
    {
        return $this->has('picture');
    }

    public function withPicture(string $url): static
    {
        return $this->withClaim('picture', $url);
    }

    public function setPicture(string $url): static
    {
        return $this->set('picture', $url);
    }

    public function withoutPicture(): static
    {
        return $this->without('picture');
    }

    public function unsetPicture(): static
    {
        return $this->unset('picture');
    }

    public function getWebsite(): ?string
    {
        return $this->get('website');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireWebsite(): string
    {
        return $this->require('website');
    }

    public function hasWebsite(): bool
    {
        return $this->has('website');
    }

    public function withWebsite(string $url): static
    {
        return $this->withClaim('website', $url);
    }

    public function setWebsite(string $url): static
    {
        return $this->set('website', $url);
    }

    public function withoutWebsite(): static
    {
        return $this->without('website');
    }

    public function unsetWebsite(): static
    {
        return $this->unset('website');
    }

    public function getEmail(): ?string
    {
        return $this->get('email');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireEmail(): string
    {
        return $this->require('email');
    }

    public function hasEmail(): bool
    {
        return $this->has('email');
    }

    public function withEmail(string $url): static
    {
        return $this->withClaim('email', $url);
    }

    public function setEmail(string $url): static
    {
        return $this->set('email', $url);
    }

    public function withoutEmail(): static
    {
        return $this->without('email');
    }

    public function unsetEmail(): static
    {
        return $this->unset('email');
    }

    public function getEmailVerified(): ?bool
    {
        return $this->get('email_verified');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireEmailVerified(): bool
    {
        return $this->require('email_verified');
    }

    public function hasEmailVerified(): bool
    {
        return $this->has('email_verified');
    }

    public function withEmailVerified(bool $value = true): static
    {
        return $this->withClaim('email_verified', $value);
    }

    public function withEmailNotVerified(): static
    {
        return $this->withClaim('email_verified', false);
    }

    public function setEmailVerified(bool $value = true): static
    {
        return $this->set('email_verified', $value);
    }

    public function setEmailNotVerified(): static
    {
        return $this->set('email_verified', false);
    }

    public function withoutEmailVerified(): static
    {
        return $this->without('email_verified');
    }

    public function unsetEmailVerified(): static
    {
        return $this->unset('email_verified');
    }

    public function getGender(): ?string
    {
        return $this->get('gender');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireGender(): string
    {
        return $this->require('gender');
    }

    public function hasGender(): bool
    {
        return $this->has('gender');
    }

    public function withGender(string $gender): static
    {
        return $this->withClaim('gender', $gender);
    }

    public function setGender(string $gender): static
    {
        return $this->set('gender', $gender);
    }

    public function withoutGender(): static
    {
        return $this->without('gender');
    }

    public function unsetGender(): static
    {
        return $this->unset('gender');
    }

    public function getBirthdate(): ?string
    {
        return $this->get('birthdate');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireBirthdate(): string
    {
        return $this->require('birthdate');
    }

    public function hasBirthdate(): bool
    {
        return $this->has('birthdate');
    }

    public function withBirthdate(string $birthdate): static
    {
        return $this->withClaim('birthdate', $birthdate);
    }

    public function setBirthdate(string $birthdate): static
    {
        return $this->set('birthdate', $birthdate);
    }

    public function withoutBirthdate(): static
    {
        return $this->without('birthdate');
    }

    public function unsetBirthdate(): static
    {
        return $this->unset('birthdate');
    }

    public function getZoneinfo(): ?string
    {
        return $this->get('zoneinfo');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireZoneinfo(): string
    {
        return $this->require('zoneinfo');
    }

    public function hasZoneinfo(): bool
    {
        return $this->has('zoneinfo');
    }

    public function withZoneinfo(string $value): static
    {
        return $this->withClaim('zoneinfo', $value);
    }

    public function setZoneinfo(string $value): static
    {
        return $this->set('zoneinfo', $value);
    }

    public function withoutZoneinfo(): static
    {
        return $this->without('zoneinfo');
    }

    public function unsetZoneinfo(): static
    {
        return $this->unset('zoneinfo');
    }

    public function getLocale(): ?string
    {
        return $this->get('locale');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireLocale(): string
    {
        return $this->require('locale');
    }

    public function hasLocale(): bool
    {
        return $this->has('locale');
    }

    public function withLocale(string $value): static
    {
        return $this->withClaim('locale', $value);
    }

    public function setLocale(string $value): static
    {
        return $this->set('locale', $value);
    }

    public function withoutLocale(): static
    {
        return $this->without('locale');
    }

    public function unsetLocale(): static
    {
        return $this->unset('locale');
    }

    public function getPhoneNumber(): ?string
    {
        return $this->get('phone_number');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requirePhoneNumber(): string
    {
        return $this->require('phone_number');
    }

    public function hasPhoneNumber(): bool
    {
        return $this->has('phone_number');
    }

    public function withPhoneNumber(string $value): static
    {
        return $this->withClaim('phone_number', $value);
    }

    public function setPhoneNumber(string $value): static
    {
        return $this->set('phone_number', $value);
    }

    public function withoutPhoneNumber(): static
    {
        return $this->without('phone_number');
    }

    public function unsetPhoneNumber(): static
    {
        return $this->unset('phone_number');
    }

    public function getPhoneNumberVerified(): ?bool
    {
        return $this->get('phone_number_verified');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requirePhoneNumberVerified(): bool
    {
        return $this->require('phone_number_verified');
    }

    public function hasPhoneNumberVerified(): bool
    {
        return $this->has('phone_number_verified');
    }

    public function withPhoneNumberVerified(bool $value = true): static
    {
        return $this->withClaim('phone_number_verified', $value);
    }

    public function withPhoneNumberNotVerified(): static
    {
        return $this->withClaim('phone_number_verified', false);
    }

    public function setPhoneNumberVerified(bool $value = true): static
    {
        return $this->set('phone_number_verified', $value);
    }

    public function setPhoneNumberNotVerified(): static
    {
        return $this->set('phone_number_verified', false);
    }

    public function withoutPhoneNumberVerified(): static
    {
        return $this->without('phone_number_verified');
    }

    public function unsetPhoneNumberVerified(): static
    {
        return $this->unset('phone_number_verified');
    }

    public function getAddress(): ?array
    {
        return $this->get('address');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAddress(): array
    {
        return $this->require('address');
    }

    public function hasAddress(): bool
    {
        return $this->has('address');
    }

    public function withAddress(array $value): static
    {
        return $this->withClaim('address', $value);
    }

    public function setAddress(string $value): static
    {
        return $this->set('address', $value);
    }

    public function withoutAddress(): static
    {
        return $this->without('address');
    }

    public function unsetAddress(): static
    {
        return $this->unset('address');
    }

    public function getUpdatedAt(bool $milliseconds = false): ?Carbon
    {
        return $this->getTimestamp('updated_at', milliseconds: $milliseconds);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireUpdatedAt(bool $milliseconds = false): Carbon
    {
        return $this->requireTimestamp('updated_at', milliseconds: $milliseconds);
    }

    public function hasUpdatedAt(): bool
    {
        return $this->has('updated_at');
    }

    public function withUpdatedAt(mixed $value, bool $milliseconds = false): static
    {
        return $this->withTimestamp('updated_at', $value, milliseconds: $milliseconds);
    }

    public function setUpdatedAt(mixed $value, bool $milliseconds = false): static
    {
        return $this->setTimestamp('updated_at', $value, milliseconds: $milliseconds);
    }

    public function withoutUpdatedAt(): static
    {
        return $this->without('updated_at');
    }

    public function unsetUpdatedAt(): static
    {
        return $this->unset('updated_at');
    }

    public function getAuthTime(bool $milliseconds = false): ?Carbon
    {
        return $this->getTimestamp('auth_time', milliseconds: $milliseconds);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAuthTime(bool $milliseconds = false): Carbon
    {
        return $this->requireTimestamp('auth_time', milliseconds: $milliseconds);
    }

    public function hasAuthTime(): bool
    {
        return $this->has('auth_time');
    }

    public function withAuthTime(mixed $value, bool $milliseconds = false): static
    {
        return $this->withTimestamp('auth_time', $value, milliseconds: $milliseconds);
    }

    public function setAuthTime(mixed $value, bool $milliseconds = false): static
    {
        return $this->setTimestamp('auth_time', $value, milliseconds: $milliseconds);
    }

    public function withoutAuthTime(): static
    {
        return $this->without('auth_time');
    }

    public function unsetAuthTime(): static
    {
        return $this->unset('auth_time');
    }


    public function getNonce(): ?string
    {
        return $this->get('nonce');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireNonce(): ?string
    {
        return $this->require('nonce');
    }

    public function hasNonce(): bool
    {
        return $this->has('nonce');
    }

    public function withNonce(string $nonce): static
    {
        return $this->withClaim('nonce', $nonce);
    }

    public function setNonce(string $nonce): static
    {
        return $this->set('nonce', $nonce);
    }

    public function withoutNonce(): static
    {
        return $this->without('nonce');
    }

    public function unsetNonce(): static
    {
        return $this->unset('nonce');
    }

    public function getAuthContextClassReference(): ?string
    {
        return $this->get('acr');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAuthContextClassReference(): ?string
    {
        return $this->require('acr');
    }

    public function hasAuthContextClassReference(): bool
    {
        return $this->has('acr');
    }

    public function withAuthContextClassReference(string $acr): static
    {
        return $this->withClaim('acr', $acr);
    }

    public function setAuthContextClassReference(string $acr): static
    {
        return $this->set('acr', $acr);
    }

    public function withoutAuthContextClassReference(): static
    {
        return $this->without('acr');
    }

    public function unsetAuthContextClassReference(): static
    {
        return $this->unset('acr');
    }


    public function getAuthMethodReferences(): Collection
    {
        return $this->getCollection('amr');
    }

    public function hasAuthMethodReferences(): bool
    {
        return $this->has('amr');
    }

    public function withAuthMethodReferences(iterable $amr): static
    {
        return $this->withClaim('amr', iterator_to_array($amr, false));
    }

    public function setAuthMethodReferences(iterable $amr): static
    {
        return $this->set('amr', iterator_to_array($amr, false));
    }

    public function containsAuthMethodReference(string $value): bool
    {
        return $this->contains('amr', $value);
    }

    public function withoutAuthMethodReferences(): static
    {
        return $this->without('amr');
    }

    public function unsetAuthMethodReferences(): static
    {
        return $this->unset('amr');
    }

    public function getAuthorizedParty(): ?string
    {
        return $this->get('azp');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAuthorizedParty(): ?string
    {
        return $this->require('azp');
    }

    public function hasAuthorizedParty(): bool
    {
        return $this->has('azp');
    }

    public function withAuthorizedParty(string $azp): static
    {
        return $this->withClaim('azp', $azp);
    }

    public function setAuthorizedParty(string $azp): static
    {
        return $this->set('azp', $azp);
    }

    public function withoutAuthorizedParty(): static
    {
        return $this->without('azp');
    }

    public function unsetAuthorizedParty(): static
    {
        return $this->unset('azp');
    }

    public function getSubJwk(): ?array
    {
        return $this->get('sub_jwk');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireSubJwk(): array
    {
        return $this->require('sub_jwk');
    }

    public function hasSubJwk(): bool
    {
        return $this->has('sub_jwk');
    }

    public function withSubJwk(array $value): static
    {
        return $this->withClaim('sub_jwk', $value);
    }

    public function setSubJwk(string $value): static
    {
        return $this->set('sub_jwk', $value);
    }

    public function withoutSubJwk(): static
    {
        return $this->without('sub_jwk');
    }

    public function unsetSubJwk(): static
    {
        return $this->unset('sub_jwk');
    }

    public function getAccessTokenHash(): ?array
    {
        return $this->get('at_hash');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireAccessTokenHash(): array
    {
        return $this->require('at_hash');
    }

    public function hasAccessTokenHash(): bool
    {
        return $this->has('at_hash');
    }

    public function withAccessTokenHash(array $value): static
    {
        return $this->withClaim('at_hash', $value);
    }

    public function setAccessTokenHash(string $value): static
    {
        return $this->set('at_hash', $value);
    }

    public function withoutAccessTokenHash(): static
    {
        return $this->without('at_hash');
    }

    public function unsetAccessTokenHash(): static
    {
        return $this->unset('at_hash');
    }

    public function getCodeHash(): ?array
    {
        return $this->get('c_hash');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireCodeHash(): array
    {
        return $this->require('c_hash');
    }

    public function hasCodeHash(): bool
    {
        return $this->has('c_hash');
    }

    public function withCodeHash(array $value): static
    {
        return $this->withClaim('c_hash', $value);
    }

    public function setCodeHash(string $value): static
    {
        return $this->set('c_hash', $value);
    }

    public function withoutCodeHash(): static
    {
        return $this->without('c_hash');
    }

    public function unsetCodeHash(): static
    {
        return $this->unset('c_hash');
    }

    public function getSessionId(): ?array
    {
        return $this->get('sid');
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireSessionId(): array
    {
        return $this->require('sid');
    }

    public function hasSessionId(): bool
    {
        return $this->has('sid');
    }

    public function withSessionId(array $value): static
    {
        return $this->withClaim('sid', $value);
    }

    public function setSessionId(string $value): static
    {
        return $this->set('sid', $value);
    }

    public function withoutSessionId(): static
    {
        return $this->without('sid');
    }

    public function unsetSessionId(): static
    {
        return $this->unset('sid');
    }
}
