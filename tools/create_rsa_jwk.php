<?php

$keys = [];

for($i = 0; $i < 16; $i++) {

    $private_key = openssl_pkey_new();
    $private_key_details = openssl_pkey_get_details($private_key);

    $private_key_pem = "";
    openssl_pkey_export($private_key, $private_key_pem);

    $public_key_pem = $private_key_details['key'];

    $rsa = $private_key_details['rsa'];
    $n = sodium_bin2base64($rsa['n'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $e = sodium_bin2base64($rsa['e'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $d = sodium_bin2base64($rsa['d'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $p = sodium_bin2base64($rsa['p'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $q = sodium_bin2base64($rsa['q'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $dp = sodium_bin2base64($rsa['dmp1'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $dq = sodium_bin2base64($rsa['dmq1'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $qi = sodium_bin2base64($rsa['iqmp'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);


    $public_key_jwk = [
        "kty" => "RSA",
        "n" => $n,
        "e" => $e,
    ];

    $keys[] = [
        "private_key" => [
            "pem" => $private_key_pem,
            "jwk" => [
                "kty" => "RSA",
                "use" => "sig",
                "n" => $n,
                "e" => $e,
                "d" => $d,
                "p" => $p,
                "q" => $q,
                "dp" => $dp,
                "dq" => $dq,
                "qi" => $qi
            ]
        ],
        "public_key" => [
            "pem" => $public_key_pem,
            "jwk" => [
                "kty" => "RSA",
                "use" => "sig",
                "n" => $n,
                "e" => $e
            ]
        ]
    ];
}

var_export($keys);
