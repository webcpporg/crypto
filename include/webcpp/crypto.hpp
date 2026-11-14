// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 Every header of webcpp::crypto that needs no backend, and the header of each
 backend the build links. It includes the default backend's header too (through
 `aes256_gcm.hpp`), so a WebAssembly program that links OpenSSL alone defines
 `WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL`, or includes the headers it uses instead.
*/
#ifndef WEBCPP_CRYPTO_HPP
#define WEBCPP_CRYPTO_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/gcm.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the system's entropy, a purpose of crypto

#if defined(WEBCPP_CRYPTO_HAS_BEARSSL)
#include <webcpp/crypto/backends/bearssl.hpp>
#endif
#if defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#endif
#if defined(WEBCPP_CRYPTO_HAS_BEARSSL) || defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#include <webcpp/crypto/aes256_gcm.hpp>
#endif

#endif  // WEBCPP_CRYPTO_HPP
