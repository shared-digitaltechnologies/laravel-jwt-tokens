<?php

namespace Shrd\Laravel\JwtTokens\Loaders\Concerns;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Shrd\Laravel\JwtTokens\Exceptions\JwtParseException;

trait WrapsTokenParser
{
    public abstract function parser(): Parser;

    /**
     * @throws JwtParseException
     */
    public function parse(string $jwt): Token
    {
        $parser = $this->parser();

        try {
            return $parser->parse($jwt);
        } catch (Exception $exception) {
            throw new JwtParseException(
                parser: $parser,
                jwt: $jwt,
                previous: $exception
            );
        }
    }

    public function tryParse(string $jwt): ?Token
    {
        try {
            return $this->parser()->parse($jwt);
        } catch (Exception) {
            return null;
        }
    }
}
