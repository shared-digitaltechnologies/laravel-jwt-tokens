<?php

namespace Shrd\Laravel\JwtTokens\Guards\Concerns;

use Illuminate\Http\Request;

trait HasRequest
{
    private ?Request $request = null;

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
        return $this;
    }
}
