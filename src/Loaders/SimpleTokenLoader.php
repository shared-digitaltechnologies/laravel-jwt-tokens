<?php

namespace Shrd\Laravel\JwtTokens\Loaders;

use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Shrd\Laravel\JwtTokens\Contracts\TokenLoader;
use Shrd\Laravel\JwtTokens\Contracts\TokenValidator;
use Shrd\Laravel\JwtTokens\Events\NewTokenLoaded;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;
use Shrd\Laravel\JwtTokens\Loaders\Concerns\WrapsTokenParser;
use Shrd\Laravel\JwtTokens\Loaders\Concerns\WrapsTokenValidator;
use Shrd\Laravel\JwtTokens\Tokens\Parser;
use Shrd\Laravel\JwtTokens\Validation\Validator;

readonly class SimpleTokenLoader implements TokenLoader
{
    use WrapsTokenParser;
    use WrapsTokenValidator;

    public function __construct(public TokenValidator $validator,
                                public ParserInterface $parser,
                                protected ?EventDispatcher $events = null)
    {
    }

    /**
     * @param TokenValidator|Constraint[] $validator
     * @param ParserInterface|Decoder|null $parser
     * @param EventDispatcher|null $events
     * @return self
     */
    public static function create(TokenValidator|array $validator = [],
                                  ParserInterface|Decoder|null $parser = null,
                                  ?EventDispatcher $events = null): self
    {
        if(is_array($validator)) $validator = new Validator($validator);

        if(!($parser instanceof ParserInterface)) $parser = new Parser($parser);

        return new self($validator, $parser, $events);
    }

    public function parser(): ParserInterface
    {
        return $this->parser;
    }

    public function validator(): TokenValidator
    {
        return $this->validator;
    }

    public function load(string $jwt): UnencryptedToken
    {
        $token = $this->validate($jwt);

        if(!($token instanceof UnencryptedToken)) {
            throw new JwtParseException(
                parser: $this->parser,
                jwt: $jwt,
                message: "The parsed ".get_class($token).' is not a '.UnencryptedToken::class,
            );
        }

        $this->events?->dispatch(new NewTokenLoaded($token));

        return $token;
    }

    public function tryLoad(string $jwt): ?UnencryptedToken
    {
        $token = $this->tryParse($jwt);
        if($token === null
            || !$this->validator()->check($token)
            || !($token instanceof UnencryptedToken)) return null;

        $this->events?->dispatch(new NewTokenLoaded($token));

        return $token;
    }



}
