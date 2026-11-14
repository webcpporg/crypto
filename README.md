# crypto

crypto gives a C++20 program the cryptography that Boost does not provide, on every target
[webcpp](https://github.com/webcpporg/webcpp) has: native (Linux, macOS, Windows with MSVC),
wasip2, wasip3 and Emscripten. It offers authenticated encryption (AES-GCM, with keys of 16, 24
and 32 bytes), a `random_device` that reads the operating system's or the browser's generator,
BIP340 Schnorr and ECDSA signatures with ECDH over secp256k1, and a constant-time `equal` for tags
and MACs. The algorithms are those of C libraries, each a backend that a program names in its own
Jamfile and that webcpp builds from its sources. Hashing and HMAC stay with Boost.Hash2.

## Backends

| Backend | Library | Brought by | Targets |
| --- | --- | --- | --- |
| `backends::bearssl` | BearSSL, MIT, commit 7bea48e5 of the mirror `webcpporg/bearssl` | built from source | native, wasip2, wasip3, emscripten |
| `backends::openssl` | OpenSSL's libcrypto, 3.5.9, Apache-2.0 | built from source, static | native, wasip2, wasip3 |
| `backends::ctaes` | ctaes as Bitcoin Core ships it, MIT | built from source | native, wasip2, wasip3, emscripten |
| `backends::secp256k1` | libsecp256k1 v0.8.0, MIT | built from source | native, wasip2, wasip3, emscripten |

OpenSSL is never the system's: the superproject builds it from `third_party/libs/openssl`
(OpenSSL 3.5.9 at `45e844f`), static, natively and on wasip2 and wasip3, and refuses it on
Emscripten (CODING-GUIDELINES.md chapter 5, rule 7).

## Building and testing

crypto lives in the superproject's `libs/crypto`. From the root of a webcpp checkout, each lane
builds from scratch:

```
b2 -a --build-dir=bin/lane-native libs/crypto/test libs/crypto/example
b2 -a --build-dir=bin/lane-wasip2 toolset=clang-wasip2 testing.launcher=tools/boost/asio-wasip2/run.sh libs/crypto/test libs/crypto/example
b2 -a --build-dir=bin/lane-wasip3 toolset=clang-wasip3 testing.launcher=tools/boost/asio-wasip3/run.sh libs/crypto/test libs/crypto/example
b2 -a --build-dir=bin/lane-emscripten toolset=emscripten libs/crypto/test libs/crypto/example
```

A program names `/webcpp/crypto//crypto` and the library of each backend it uses.

## Documentation

The page is published at <https://webcpporg.github.io/libs/crypto/>.

## Licence

crypto is under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`). The backends keep
their own: BearSSL is MIT, ctaes is MIT, libsecp256k1 is MIT and OpenSSL is Apache-2.0.
