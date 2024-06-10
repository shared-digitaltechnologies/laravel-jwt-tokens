<?php

namespace Shrd\Laravel\JwtTokens\Validation\Constraints;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\Contracts\IssuesTokens;
use Shrd\Laravel\JwtTokens\Contracts\KeySetResolver;
use Shrd\Laravel\JwtTokens\Exceptions\KeySetLoadException;
use Shrd\Laravel\JwtTokens\Keys\Sets\KeySet;
use WeakMap;

class IssuedAndSignedBy implements Constraint
{
    /**
     * @var WeakMap<IssuesTokens, SignedWith>
     */
    private WeakMap $signedWithConstraints;

    /**
     * @param IssuesTokens[] $issuers
     */
    public function __construct(protected KeySetResolver $keySetResolver,
                                protected array $issuers)
    {
        $this->signedWithConstraints = new WeakMap();
    }

    /**
     * @throws KeySetLoadException
     */
    private function getIssuerKeySet(IssuesTokens $issuer): KeySet
    {
        $descriptor = $issuer->jwtVerificationKeySet();
        if($descriptor instanceof KeySet) return $descriptor;

        if(is_string($descriptor)) return $this->keySetResolver->get($descriptor);

        return $this->keySetResolver->combine(...$descriptor);
    }

    /**
     * @throws KeySetLoadException
     */
    private function getSignedWithConstraintFor(IssuesTokens $issuer): SignedWith
    {
        if(isset($this->signedWithConstraints[$issuer])) {
            return $this->signedWithConstraints[$issuer];
        }

        $constraint = new SignedWith($this->getIssuerKeySet($issuer));
        $this->signedWithConstraints[$issuer] = $constraint;
        return $constraint;
    }

    /**
     * @param Token $token
     * @return void
     * @throws KeySetLoadException
     * @throws IssuedAndSignedByConstraintViolation
     * @throws EmptyConstraintViolation
     */
    public function assert(Token $token): void
    {
        if(count($this->issuers) === 0) {
            throw new EmptyConstraintViolation(
                static::class,
                "No issuers are allowed to sign tokens. (equivalent to empty constraint, thus always violated.)"
            );
        }

        if(! $token instanceof UnencryptedToken ) {
            throw new \Lcobucci\JWT\Validation\ConstraintViolation("Pass an unencrypted token.", static::class);
        }

        /**
         * @var array<array-key, ConstraintViolation> $violations
         */
        $violations = [];

        foreach ($this->issuers as $ix => $issuer) {
            if($issuer->couldHaveIssuedTokenClaims($token->claims())) {
                try {
                    $this->getSignedWithConstraintFor($issuer)->assert($token);
                    return;
                } catch (ConstraintViolation $violation) {
                    $violations[$ix] = $violation;
                } catch (\Lcobucci\JWT\Validation\ConstraintViolation $violation) {
                    $violations[$ix] = new WrappedConstraintViolation($violation);
                }
            } else {
                $violations[$ix] = new NotIssuedByConstraintViolation(static::class, $issuer);
            }
        }

        if(count($violations) === 1) {
            throw array_values($violations)[0];
        } else {
            throw new IssuedAndSignedByConstraintViolation(static::class, $this->issuers, $violations);
        }

    }
}
