<?php

$keys = require __DIR__.'/../tests/fixtures/rsa_key_pairs.php';

$key = $keys[0];

$private_key = openssl_pkey_get_private($key['private_key']['pem']);

$headers = [
    "typ" => "JWT",
    "alg" => "RS256",
];

$encoded_headers = sodium_bin2base64(json_encode($headers), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

$claims = [
    "sub" => "test"
];

$encoded_claims = sodium_bin2base64(json_encode($claims), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

$payload = "$encoded_headers.$encoded_claims";

openssl_sign($payload, $signature, $private_key, OPENSSL_ALGO_SHA256);

$encoded_signature = sodium_bin2base64($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);

echo "$payload.$encoded_signature";
