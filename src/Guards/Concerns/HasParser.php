<?php

namespace Shrd\Laravel\JwtTokens\Guards\Concerns;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Events\JwtFailedToParse;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;

trait HasParser
{
    use DispatchesEvents;

    private Parser $parser;

    public function setParser(Parser $parser): static
    {
        $this->parser = $parser;
        return $this;
    }

    public function getParser(): Parser
    {
        return $this->parser;
    }

    /**
     * @throws JwtParseException
     */
    protected function parse(string $jwt): Token
    {
        $parser = $this->parser;
        try {
            return $parser->parse($jwt);
        } catch (Exception $exception) {
            $this->dispatchEvent(new JwtFailedToParse(
                guard: $this->guardName(),
                parser: $parser,
                jwt: $jwt,
                exception: $exception
            ));

            throw new JwtParseException(
                parser: $parser,
                jwt: $jwt,
                message: "Bad Token",
                previous: $exception
            );
        }
    }

    protected function tryParse(string $jwt): ?Token
    {
        $parser = $this->parser;
        try {
            return $parser->parse($jwt);
        } catch (Exception $exception) {
            $this->dispatchEvent(new JwtFailedToParse(
                guard: $this->guardName(),
                parser: $parser,
                jwt: $jwt,
                exception: $exception
            ));

            return null;
        }
    }
}
