<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

class CachedVerificationKey implements VerificationKey
{
    protected ?string $kid;
    protected array $algs;
    protected string $content;
    protected string $passphrase;

    public function __construct(VerificationKey $key)
    {
        $this->kid = $key->getKeyId();

        $this->algs = [];
        foreach (Algorithm::cases() as $algorithm) {
            if($key->supportedByAlgorithm($algorithm)) {
                $this->algs[] = $algorithm->value;
            }
        }

        $this->content = $key->contents();
        $this->passphrase = $key->passphrase();
    }


    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    public function contents(): string
    {
        return $this->content;
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return in_array($algorithm->value, $this->algs);
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }
}
