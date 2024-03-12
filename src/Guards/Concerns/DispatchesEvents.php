<?php

namespace Shrd\Laravel\JwtTokens\Guards\Concerns;

use Illuminate\Contracts\Events\Dispatcher;

trait DispatchesEvents
{
    private ?Dispatcher $events = null;

    public function getDispatcher(): ?Dispatcher
    {
        return $this->events;
    }

    public function setDispatcher(?Dispatcher $dispatcher): static
    {
        $this->events = $dispatcher;
        return $this;
    }

    public abstract function guardName(): string;

    protected function dispatchEvent($event): void
    {
        $this->events?->dispatch($event);
    }
}
