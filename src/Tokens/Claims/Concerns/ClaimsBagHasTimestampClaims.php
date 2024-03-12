<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Carbon;
use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;

trait ClaimsBagHasTimestampClaims
{
    /**
     * Gets the provided claim as a carbon value.
     *
     * @param string $name
     * @param bool $milliseconds
     * @return Carbon|null
     */
    public function getTimestamp(string $name,
                                 bool $milliseconds = false): ?Carbon
    {
        $value = $this->get($name);
        if($value === null) return null;
        return $milliseconds ? Carbon::createFromTimestampMs($value) : Carbon::createFromTimestamp($value);
    }

    public function getTimestampMs(string $name): ?Carbon
    {
        return $this->getTimestamp($name, milliseconds: true);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireTimestamp(string $name,
                                     bool   $milliseconds = false): Carbon
    {
        $value = $this->require($name);
        return $milliseconds ? Carbon::createFromTimestampMs($value): Carbon::createFromTimestamp($value);
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireTimestampMs(string $name): Carbon
    {
        return $this->requireTimestamp($name, milliseconds: true);
    }

    public function withTimestamp(string $name,
                                  mixed $value,
                                  bool $milliseconds = false): static
    {
        if(is_numeric($value)) $value = intval($value);
        else $value = $milliseconds ? Carbon::make($value)->getTimestampMs() : Carbon::make($value)->getTimestamp();
        return $this->withClaim($name, $value);
    }

    public function withTimestampMs(string $name,
                                    mixed $value): static
    {
        return $this->withTimestamp($name, $value, milliseconds: true);
    }

    public function setTimestamp(string $name,
                                 mixed $value,
                                 bool $milliseconds = false): static
    {
        if(is_numeric($value)) $value = intval($value);
        else $value = $milliseconds ? Carbon::make($value)->getTimestampMs() : Carbon::make($value)->getTimestamp();
        return $this->withClaim($name, $value);
    }

    public function setTimestampMs(string $name,
                                   mixed $value): static
    {
        return $this->setTimestamp($name, $value);
    }
}
