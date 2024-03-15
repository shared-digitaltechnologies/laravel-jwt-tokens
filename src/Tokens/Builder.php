<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use Carbon\CarbonInterval;
use Carbon\FactoryImmutable;
use DateInterval;
use DateTimeInterface;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Carbon;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer as AlgorithmImplementation;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\UnencryptedToken;
use Psr\Clock\ClockInterface;
use Shrd\Laravel\JwtTokens\Contracts\SignerRegistry;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Signers\NoneSigner;
use Shrd\Laravel\JwtTokens\Signers\Signer;

readonly class Builder implements BuilderInterface
{
    private function __construct(protected SignerRegistry $signerRegistry,
                                 protected Encoder $encoder,
                                 protected ClockInterface $clock,
                                 protected ?DateInterval $defaultExpiresIn,
                                 protected Signer $signer,
                                 protected array $headers,
                                 protected array $claims)
    {
    }

    public static function create(SignerRegistry $signerRegistry,
                                  ?Encoder $encoder = null,
                                  ?ClockInterface $clock = null,
                                  DateInterval|null $defaultExpiresIn = null,
                                  ?Signer $signer = null,
                                  array $headers = [],
                                  array $claims = []): static
    {
        $encoder ??= new JoseEncoder;
        $clock   ??= new FactoryImmutable;
        $signer  ??= $signerRegistry->signer();

        return new static(
            signerRegistry: $signerRegistry,
            encoder: $encoder,
            clock: $clock,
            defaultExpiresIn: $defaultExpiresIn,
            signer: $signer,
            headers: $headers,
            claims: $claims
        );
    }

    public function audience(string|array $audience): static
    {
        return $this->withClaim('aud', $audience);
    }

    public function nonce(string $nonce): static
    {
        return $this->withClaim('nonce', $nonce);
    }

    public function permittedFor(string ...$audiences): static
    {
        if(count($audiences) === 0) return $this;

        $oldAudiences = $this->claims['aud'] ?? null;
        if($oldAudiences === null) $oldAudiences = [];
        else if(is_string($oldAudiences)) $oldAudiences = [$oldAudiences];

        $audiences = array_unique([
            ...$oldAudiences,
            ...array_values($audiences)
        ]);

        assert($audiences > 0);

        if (count($audiences) === 1) {
            return $this->audience($audiences[0]);
        } else {
            return $this->audience($audiences);
        }
    }

    protected function toUnixTimestamp(DateTimeInterface|string|int|null $value): int
    {
        if(is_null($value)) {
            return $this->clock->now()->getTimestamp();
        }

        if(is_int($value)) {
            return $value;
        }

        if(is_string($value)) {
            return Carbon::make($value)->getTimestamp();
        }

        return $value->getTimestamp();
    }

    public function expiresAt(DateTimeInterface|string|int $expiration): static
    {
        return $this->withClaim('exp', $this->toUnixTimestamp($expiration));
    }

    public function expiresIn(DateInterval|string|int|null $interval): static
    {
        if(!is_null($interval)) {
            if(is_numeric($interval)) $interval = CarbonInterval::seconds($interval);
            if(is_string($interval)) $interval = CarbonInterval::make($interval);

            if(array_key_exists('exp', $this->claims)) {
                return $this->expiresAt($this->clock->now()->add($interval));
            }
        }

        return $this->withExpiresIn($interval);
    }

    public function identifiedBy(string $id): static
    {
        return $this->withClaim('jti', $id);
    }

    public function issuedAt(DateTimeInterface|string|int|null $issuedAt = null): static
    {
        return $this->withClaim('iat', $this->toUnixTimestamp($issuedAt));
    }

    public function issuedBy(string $issuer): static
    {
        return $this->withClaim('iss', $issuer);
    }

    public function notBefore(DateTimeInterface|string|int|null $notBefore = null): static
    {
        return $this->canOnlyBeUsedAfter($notBefore);
    }

    public function canOnlyBeUsedAfter(DateTimeInterface|string|int|null $notBefore = null): static
    {
        return $this->withClaim('nbf', $this->toUnixTimestamp($notBefore));
    }

    public function subject(string $subject): static
    {
        return $this->relatedTo($subject);
    }

    public function relatedTo(string $subject): static
    {
        return $this->withClaim('sub', $subject);
    }

    public function signedWith(Signer|string|null $signer): static
    {
        if(is_string($signer) || is_null($signer)) {
            $signer = $this->signerRegistry->signer($signer);
        }

        return $this->withSigner($signer);
    }

    public function withoutSignature(): static
    {
        return $this->withSigner(new NoneSigner);
    }

    public function signedUsing(AlgorithmImplementation|string $algorithm,
                                Key|KeySet|string              $key,
                                string|null                    $kid = null): static
    {
        return $this->withSigner(
            $this->signerRegistry->signerUsing($algorithm, $key, $kid)
        );
    }

    public function withHeader(string $name, mixed $value): static
    {
        $headers = $this->headers;
        $headers[$name] = $value;
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $this->defaultExpiresIn,
            signer: $this->signer,
            headers: $headers,
            claims: $this->claims,
        );
    }

    public function withClaim(string $name, mixed $value): static
    {
        $claims = $this->claims;
        $claims[$name] = $value;
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $this->defaultExpiresIn,
            signer: $this->signer,
            headers: $this->headers,
            claims: $claims,
        );
    }

    public function withHeaders(Arrayable|iterable $headers): static
    {
        if($headers instanceof Arrayable) $headers = $headers->toArray();
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $this->defaultExpiresIn,
            signer: $this->signer,
            headers: [...$this->headers, ...$headers],
            claims: $this->claims,
        );
    }

    public function withClaims(Arrayable|iterable $claims): static
    {
        if($claims instanceof Arrayable) $claims = $claims->toArray();
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $this->defaultExpiresIn,
            signer: $this->signer,
            headers: $this->headers,
            claims: [...$this->claims, ...$claims]
        );
    }

    protected function withExpiresIn(?DateInterval $expiresIn): static
    {
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $expiresIn,
            signer: $this->signer,
            headers: $this->headers,
            claims: $this->claims,
        );
    }

    protected function withSigner(Signer $signer): static
    {
        return new static(
            signerRegistry: $this->signerRegistry,
            encoder: $this->encoder,
            clock: $this->clock,
            defaultExpiresIn: $this->defaultExpiresIn,
            signer: $signer,
            headers: $this->headers,
            claims: $this->claims
        );
    }

    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items)
        );
    }

    private function getHeaders(string $alg, ?string $kid = null): DataSet
    {
        $headers = $this->headers;
        $headers['alg'] = $alg;
        if($kid !== null) {
            $headers['kid'] = $kid;
        }

        if(empty($headers['typ'])) {
            $headers['typ'] = 'JWT';
        }

        return new DataSet(
            $headers,
            $this->encode($headers)
        );
    }

    private function getClaims(): DataSet
    {
        $claims = $this->claims;

        if(!array_key_exists('iat', $claims)) {
            $claims['iat'] = $this->clock->now()->getTimestamp();
        }

        if(!array_key_exists('nbf', $claims)) {
            $claims['nbf'] = $claims['iat'];
        }

        if(!array_key_exists('exp', $claims) && $this->defaultExpiresIn !== null) {
            $claims['exp'] = Carbon::createFromTimestamp($claims['nbf'])
                ->add($this->defaultExpiresIn)
                ->getTimestamp();
        }

        return new DataSet(
            $claims,
            $this->encode($claims)
        );
    }

    public function sign(Signer|string|null $signer = null): UnencryptedToken
    {
        if(is_null($signer)) {
            $signer = $this->signer;
        }

        if(!($signer instanceof Signer)) {
            $signer = $this->signerRegistry->signer($signer);
        }

        $headers = $this->getHeaders(
            alg: $signer->algorithmId(),
            kid: $signer->keyId(),
        );

        $claims = $this->getClaims();

        $signature = $signer->sign($headers->toString().'.',$claims->toString());
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Token(
            $headers,
            $claims,
            new Signature($signature, $encodedSignature)
        );
    }

    public function signUsing(AlgorithmImplementation|string $algorithm,
                              Key|KeySet|string              $key,
                              string|null                    $kid = null): UnencryptedToken
    {
        return $this->sign($this->signerRegistry->signerUsing($algorithm, $key, $kid));
    }

    public function getToken(AlgorithmImplementation|Signer|string|null $signer = null,
                             Key|KeySet|string|null                     $key = null,
                             string|null                                $kid = null): UnencryptedToken
    {
        if($signer instanceof Signer || is_null($signer) || is_string($signer) && is_null($key)) {
            return $this->sign($signer);
        } else {
            return $this->signUsing($signer, $key, $kid);
        }
    }
}
