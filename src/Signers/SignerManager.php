<?php

namespace Shrd\Laravel\JwtTokens\Signers;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Str;
use Lcobucci\JWT\Signer\Key;
use RuntimeException;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Contracts\SignerRegistry;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Keys\NoneKey;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use Shrd\Laravel\JwtTokens\Keys\VerificationKey;
use Lcobucci\JWT\Signer as AlgorithmImplementation;

class SignerManager implements SignerRegistry
{
    protected string $defaultSigner;

    protected array $signers = [];

    protected array $signerConfigs = [];

    protected array $customDrivers = [];

    public function __construct(protected Container $container,
                                protected KeySetResolver $keySetResolver,
                                ConfigRepository $config)
    {
        $this->defaultSigner = $config->get('jwt.signer', 'default');
        $this->signerConfigs = $config->get('jwt.signers', fn() => [
            "default" => [
                "algorithm" => "HS256",
                "key" => $config->get('app.key'),
            ]
        ]);
    }

    public function setKeySetResolver(KeySetResolver $keySetResolver): static
    {
        $this->keySetResolver = $keySetResolver;
        return $this;
    }

    public function extend(string $driver, callable $callback): static
    {
        $this->customDrivers[$driver] = $callback(...);
        return $this;
    }

    public function get(?string $signer = null): Signer | Verifier
    {
        $signer ??= $this->defaultSigner;

        if(array_key_exists($signer, $this->signers)) {
            return $this->signers[$signer];
        }

        if(array_key_exists($signer, $this->signerConfigs)) {
            $result = $this->create($this->signerConfigs[$signer]);
            $this->signers[$signer] = $result;
            return $result;
        }

        if($signer === 'none') {
           return new NoneSigner;
        }

        throw new RuntimeException("Signer '$signer' unknown.");
    }

    public function signer(?string $signer = null): Signer
    {
        return $this->get($signer);
    }

    public function verifier(?string $signer = null): Verifier
    {
        return $this->get($signer);
    }

    protected function create(array $config): Signer | Verifier
    {
        $driver = $config['driver'] ?? 'algorithm';

        if(array_key_exists($driver, $this->customDrivers)) {
            return $this->customDrivers[$driver]($this->container, $config);
        }

        $method = 'create'.Str::studly($driver).'Signer';
        if(method_exists($this, $method)) {
            return $this->$method($config);
        }

        throw new RuntimeException("Unknown signer driver '$driver'.");
    }

    private function resolveKey(mixed $key, ?string $kid = null, ?Algorithm $algorithm = null): Key
    {
        if($key instanceof Key) return $key;

        if(is_string($key)) $key = $this->keySetResolver->get($key);
        if(is_array($key)) $key = $this->keySetResolver->combine(...$key);

        if($key instanceof KeySet) {
            if($kid !== null) {
                $result = $key->getKeyById($kid);
                if($result === null) {
                    throw new RuntimeException("Key with key id '$kid' not found in key set.");
                }
            } else {
                $iter = $algorithm ? $key->forAlgorithm($algorithm) : $key;
                foreach ($iter as $item) {
                    return $item;
                }
            }
        }

        throw new RuntimeException("Could not resolve key from ".get_debug_type($key));
    }

    private function resolveAlgorithmFromKeys(VerificationKey $verificationKey, Key $signingKey): Algorithm
    {
        if($verificationKey === $signingKey) {
            foreach (Algorithm::symmetricCases() as $case) {
                if($verificationKey->supportedByAlgorithm($case)) {
                    return $case;
                }
            }
        } else {
            foreach (Algorithm::asymmetricCases() as $case) {
                if($verificationKey->supportedByAlgorithm($case)) {
                    return $case;
                }
            }
        }

        foreach (Algorithm::cases() as $case) {
            if($verificationKey->supportedByAlgorithm($case)) {
                return $case;
            }
        }
        throw new RuntimeException("No algorithm found for key ".get_debug_type($verificationKey));
    }

    protected function createAlgorithmSigner(array $config): SymmetricSigner | AsymmetricSigner
    {
        $kid = $config['kid'] ?? $config['key_id'] ?? null;
        $algorithm = $config['alg'] ?? $config['algorithm'] ?? null;

        $optimisticAlgorithm = Algorithm::tryFrom($algorithm);

        $verificationKey = $config['verification_key'] ?? $config['public_key'] ?? $config['key'] ?? new NoneKey;
        $verificationKey = $this->resolveKey($verificationKey, $kid, $optimisticAlgorithm);

        $signingKey = $config['signing_key'] ?? $config['private_key'] ?? $config['key'] ?? $verificationKey;
        $signingKey = $this->resolveKey($signingKey, $kid, $optimisticAlgorithm);

        /** @var VerificationKey $verificationKey */
        $algorithm ??= $this->resolveAlgorithmFromKeys($verificationKey, $signingKey);

        if($algorithm->usesSymmetricKey()) {
            return new SymmetricSigner($algorithm->getImplementation(), $signingKey);
        } else {
            return new AsymmetricSigner($algorithm->getImplementation(), $signingKey, $verificationKey);
        }
    }

    protected function createNoneSigner(array $config): NoneSigner
    {
        return new NoneSigner;
    }

    public function signerUsing(AlgorithmImplementation|string $algorithm,
                                Key|KeySet|string $key,
                                ?string $kid = null): Signer
    {
        $key = $this->resolveKey($key, $kid, Algorithm::tryFromImplOrId($algorithm));

        $algorithm = is_string($algorithm) ? Algorithm::from($algorithm) : $algorithm;
        assert($algorithm instanceof AlgorithmImplementation);

        return new WrappedSigner($algorithm, $key, $kid);
    }

    /**
     * @throws KeySetLoadException
     */
    public function verifierUsing(AlgorithmImplementation|string $algorithm, Key|KeySet|string $key): Verifier
    {
        if(is_string($algorithm)) $algorithm = Algorithm::from($algorithm);
        if(is_string($key)) $key = $this->keySetResolver->get($key);
        return new WrappedVerifier($algorithm, $key);
    }
}
