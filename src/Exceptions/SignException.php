<?php

namespace Shrd\Laravel\JwtTokens\Exceptions;

use Shrd\Laravel\JwtTokens\Signers\Signer;

interface SignException extends JwtException
{
    public function getSigner(): Signer;

    public function getPayload(): string;
}
