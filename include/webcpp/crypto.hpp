// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Every header of webcpp::crypto that needs no backend, and the header of each
 backend the build links. `ciphers/aes256_gcm.hpp`, `aes128_gcm` and `aes256_gcm`, is
 included when the default backend is linked: a program that links OpenSSL alone where
 BearSSL is the default (WebAssembly, or `WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL`) names
 `ciphers::gcm<ciphers::aes256<backends::openssl>>`.
*/
#ifndef WEBCPP_CRYPTO_HPP
#define WEBCPP_CRYPTO_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the system's entropy, a purpose of crypto

#ifdef WEBCPP_CRYPTO_HAS_BEARSSL
#include <webcpp/crypto/backends/bearssl.hpp>
#endif
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
#include <webcpp/crypto/backends/openssl.hpp>
#endif
#if (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)) || \
    (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BEARSSL) && defined(WEBCPP_CRYPTO_HAS_BEARSSL))
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#endif

#ifdef WEBCPP_CRYPTO_HAS_CTAES
#include <webcpp/crypto/backends/ctaes.hpp>
#endif

#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
#include <webcpp/crypto/curves/secp256k1.hpp>
#endif

#endif  // WEBCPP_CRYPTO_HPP
