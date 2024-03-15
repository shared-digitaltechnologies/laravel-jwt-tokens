<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use DateTimeInterface;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\UnencryptedToken;

readonly class CacheLoadedToken extends Token
{
    public int $firstLoadedAt;

    public function __construct(DataSet $headers,
                                DataSet $claims,
                                Signature $signature,
                                public string $loaderName,
                                ?int $firstLoadedAt = null,
                                public bool $restoredFromCache = false)
    {
        $this->firstLoadedAt = $firstLoadedAt ?? Carbon::now()->getTimestamp();
        parent::__construct($headers, $claims, $signature);
    }

    public static function initUsingUnencryptedToken(UnencryptedToken   $token,
                                                     string             $loaderName,
                                                     ?int               $firstLoadedAt = null): self
    {
        return new self(
            headers: $token->headers(),
            claims: $token->claims(),
            signature: $token->signature(),
            loaderName: $loaderName,
            firstLoadedAt: $firstLoadedAt,
            restoredFromCache: false
        );
    }

    public static function restoreCacheArray(array $cacheArray): self
    {
        [
            "c" => $claims,
            "ec" => $encodedClaims,
            "h" => $headers,
            "eh" => $encodedHeaders,
            "s" => $signature,
            "es" => $encodedSignature,
            "fla" => $firstLoadedAt,
            "ln" => $loaderName,
        ] = $cacheArray;

        return new self(
            headers: new DataSet($headers, $encodedHeaders),
            claims: new DataSet($claims, $encodedClaims),
            signature: new Signature($signature, $encodedSignature),
            loaderName: $loaderName,
            firstLoadedAt: $firstLoadedAt,
            restoredFromCache: true
        );
    }

    public function toCacheArray(): array
    {
        return [
            "c" => $this->claims()->all(),
            "ec" => $this->claims()->toString(),
            "h" => $this->headers()->all(),
            "eh" => $this->headers()->toString(),
            "s" => $this->signature()->hash(),
            "es" => $this->signature()->toString(),
            "fla" => $this->firstLoadedAt,
            "ln" => $this->loaderName,
        ];
    }

    public function firstLoadedAt(): Carbon
    {
        return Carbon::createFromTimestamp($this->firstLoadedAt);
    }

    public function isRestoredFromCache(): bool
    {
        return $this->restoredFromCache;
    }

    public function validatedByLoader(): string
    {
        return $this->loaderName;
    }
}
