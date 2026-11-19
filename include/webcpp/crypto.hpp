// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Every header of webcpp::crypto that needs no backend, the header of each backend the build links
 with what it alone holds (libsecp256k1's secp256k1; libsodium's Ed25519 and X25519 with their key
 formats, `crypto_kx`, boxes and sealed boxes), `ciphers/aes256_gcm.hpp`, whose `aes128_gcm` and
 `aes256_gcm` name AES-GCM's default backend, and `ciphers/chacha20_poly1305.hpp`,
 `ciphers/secretbox.hpp` and `pem.hpp`, whose AEADs and PEM name libsodium: a program that does
 not link the default names another in the type, as
 `ciphers::gcm<ciphers::aes256<backends::openssl>>` on WebAssembly or
 `ciphers::chacha20_poly1305<backends::bearssl>`, or, for the original ChaCha20-Poly1305,
 XChaCha20-Poly1305 and the secret boxes, which libsodium alone has, links libsodium.
*/
#ifndef WEBCPP_CRYPTO_HPP
#define WEBCPP_CRYPTO_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the system's entropy, a purpose of crypto
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/supports.hpp>

#ifdef WEBCPP_CRYPTO_HAS_BEARSSL
#include <webcpp/crypto/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
#include <webcpp/crypto/backends/openssl.hpp>
#endif

#ifdef WEBCPP_CRYPTO_HAS_CTAES
#include <webcpp/crypto/backends/ctaes.hpp>
#endif

#ifdef WEBCPP_CRYPTO_HAS_SODIUM
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#endif

#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
#include <webcpp/crypto/curves/secp256k1.hpp>
#endif

#endif  // WEBCPP_CRYPTO_HPP
