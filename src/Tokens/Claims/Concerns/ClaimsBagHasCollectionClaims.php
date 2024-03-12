<?php

namespace Shrd\Laravel\JwtTokens\Tokens\Claims\Concerns;

use Illuminate\Support\Collection;
use Shrd\Laravel\JwtTokens\Exceptions\ClaimMissingException;

trait ClaimsBagHasCollectionClaims
{
    public function getFirst(string $name): mixed
    {
        $value = $this->get($name);
        if(is_array($value)) return $value[0] ?? null;
        return $value;
    }

    /**
     * @throws ClaimMissingException
     */
    public function requireFirst(string $name): mixed
    {
        $value = $this->getFirst($name);
        if($value !== null) return $value;

        throw new ClaimMissingException(
            claimName: $name,
            claims: $this
        );
    }

    public function exists(string $name): bool
    {
        return $this->getFirst($name) !== null;
    }

    public function getCollection(string $name): Collection
    {
        $value = $this->get($name, default: []);
        if(!is_array($value)) $value = [$value];
        return Collection::make($value);
    }

    public function setCollection(string $name, mixed $value, bool $unique = false): static
    {
        if(is_null($value)) $items = [];
        else if(is_iterable($value)) $items = array_values(iterator_to_array($value));
        else $items = [$value];

        if($unique) $items = array_unique($items);

        if(count($items) === 0) return $this->unset($name);
        if (count($items) === 1) return $this->set($name, $items[0]);
        return $this->set($name, $items);
    }

    public function withCollection(string $name, mixed $value, bool $unique = false): static
    {
        $result = clone $this;

        return $result->setCollection($name, $value, unique: $unique);
    }

    public function add(string $name, mixed $value, bool $unique = false): static
    {
        $items = $this->getCollection($name)->all();

        if(!$unique || !in_array($value, $items)) {
            $items[] = $value;
        }
        return $this->setCollection($name, $items, unique: $unique);
    }

    public function remove(string $name, mixed $value): static
    {
        $items = $this->getCollection($name)->filter(fn($val) => $value !== $val)->all();
        return $this->setCollection($name, $items);
    }

    public function withAdded(string $name, mixed $value, bool $unique = false): static
    {
        $result = clone $this;

        return $result->add($name, $value, $unique);
    }

    public function withRemoved(string $name, mixed $value): static
    {
        $result = clone $this;

        return $result->remove($name, $value);
    }

    public function contains(string $name, mixed $value): bool
    {
        return $this->getCollection($name)->contains($value);
    }
}
