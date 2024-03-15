<?php

namespace Shrd\Laravel\JwtTokens\Tokens;

use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as BaseToken;

readonly class Parser implements ParserInterface
{
    public function __construct(protected Decoder $decoder)
    {
    }

    public static function create(?Decoder $decoder = null): self
    {
        return new self($decoder ?? new JoseEncoder);
    }

    /**
     * @param string $jwt
     * @return array{string, string, string}
     *
     * @throws BaseToken\InvalidTokenStructure
     */
    private function splitJwt(string $jwt): array
    {
        $data = explode('.', $jwt);

        if(count($data) !== 3) {
            throw BaseToken\InvalidTokenStructure::missingOrNotEnoughSeparators();
        }

        return $data;
    }

    /**
     * @param string $jwt
     * @return Token
     * @throws BaseToken\InvalidTokenStructure
     * @throws BaseToken\UnsupportedHeaderFound
     */
    public function parse(string $jwt): Token
    {
        [$encodedHeader, $encodedClaims, $encodedSignature] = $this->splitJwt($jwt);

        if($encodedHeader === '') throw BaseToken\InvalidTokenStructure::missingHeaderPart();
        if($encodedClaims === '') throw BaseToken\InvalidTokenStructure::missingClaimsPart();

        $header = $this->parseHeader($encodedHeader);
        $claims = $this->parseClaims($encodedClaims);
        $signature = $this->parseSignature($encodedSignature);

        return new Token($header, $claims, $signature);
    }

    /**
     * @param string $encodedHeader
     * @return BaseToken\DataSet
     * @throws BaseToken\InvalidTokenStructure
     * @throws BaseToken\UnsupportedHeaderFound
     */
    private function parseHeader(string $encodedHeader): BaseToken\DataSet
    {
        $header = $this->decoder->jsonDecode(
            $this->decoder->base64UrlDecode($encodedHeader)
        );

        $this->ensureValidDataArray($header, 'headers');

        if(array_key_exists('enc', $header)) {
            throw BaseToken\UnsupportedHeaderFound::encryption();
        }

        return new BaseToken\DataSet($header, $encodedHeader);
    }

    private function parseClaims(string $encodedClaims): BaseToken\DataSet
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($encodedClaims));

        $this->ensureValidDataArray($claims, 'claims');

        return new BaseToken\DataSet($claims, $encodedClaims);
    }

    /**
     * @param mixed $array
     * @param non-empty-string $part
     * @throws BaseToken\InvalidTokenStructure
     *
     * @phpstan-assert array<non-empty-string, mixed> $array
     */
    private function ensureValidDataArray(mixed $array, string $part): void
    {
        if(!is_array($array)) {
            throw BaseToken\InvalidTokenStructure::arrayExpected($part);
        }

        foreach ($array as $key => $value) {
            if (!is_string($key) || $key === '') {
                throw BaseToken\InvalidTokenStructure::arrayExpected($part);
            }
        }
    }

    private function parseSignature(string $data): BaseToken\Signature
    {
        $hash = $this->decoder->base64UrlDecode($data);

        return new BaseToken\Signature($hash, $data);
    }
}
