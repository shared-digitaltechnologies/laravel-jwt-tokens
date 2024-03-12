<?php

namespace Shrd\Laravel\JwtTokens\Keys;

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;
use Shrd\Laravel\JwtTokens\Algorithms\Algorithm;

class WrappedAsymmetricKey implements VerificationKey
{
    public function __construct(protected AsymmetricKey $key, protected ?string $kid = null)
    {
    }

    public function toString(?string $format = 'PKCS8', array $options = []): string
    {
        return $this->key->toString($format, $options);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function contents(): string
    {
        return $this->toString();
    }

    public function passphrase(): string
    {
        return '';
    }

    public function getLoadedFormat(): string
    {
        return $this->key->getLoadedFormat();
    }

    public function getComment(): ?string
    {
        return $this->key->getComment();
    }

    public function getPublicKey(): ?PublicKey
    {
        $key = $this->key;
        if($key instanceof PrivateKey) {
            $key = $key->getPublicKey();
        }
        if($key instanceof PublicKey) {
            return $key;
        }
        return null;
    }

    public function getFingerprint(string $algorithm = 'md5'): ?string
    {
        return $this->getPublicKey()?->getFingerprint($algorithm);
    }

    public function getKeyType(): ?KeyType
    {
        $key = $this->key;
        if($key instanceof RSA) {
            return KeyType::RSA;
        }

        if($key instanceof EC) {
            $curve = $key->getCurve();
            if($curve instanceof EC\BaseCurves\TwistedEdwards) {
                return KeyType::OKP;
            } else {
                return KeyType::EC;
            }
        }

        return null;
    }

    public function getKeyId(): ?string
    {
        return $this->kid;
    }

    public function supportedByAlgorithm(Algorithm $algorithm): bool
    {
        return $this->getKeyType()?->isSupportedByAlgorithm($algorithm) ?? false;
    }
}
