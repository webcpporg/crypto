// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `aes128_gcm` and `aes256_gcm` on AES-GCM's default backend, whose header it includes when the
 program links it: natively OpenSSL, on wasip2, wasip3 and Emscripten BearSSL, whatever else the
 program links (`default_backend_t<families::gcm>`). A program that uses them without linking
 the default stops where it calls them, with the Jamfile line that links it and the type that
 names another backend, as `gcm<aes256<backends::bearssl>>`.

 On MSVC, wasip2 and wasip3 the source-built OpenSSL is compiled without assembly: AES is
 table-driven, GHASH is 4-bit tables, there is no AES-NI, and none of it is constant time.
 On MSVC the default is OpenSSL all the same, so a program that wants BearSSL there names
 `gcm<aes256<backends::bearssl>>`.

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_AES256_GCM_HPP
#define WEBCPP_CRYPTO_CIPHERS_AES256_GCM_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/detail/defaults.hpp>

#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_OPENSSL) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#elif defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_BEARSSL) && defined(WEBCPP_CRYPTO_HAS_BEARSSL)
#include <webcpp/crypto/backends/bearssl.hpp>
#endif

namespace webcpp::crypto::ciphers {

/** AES-128-GCM on the default backend. */
using aes128_gcm = gcm<aes128<>>;
/** AES-256-GCM on the default backend. */
using aes256_gcm = gcm<aes256<>>;

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_AES256_GCM_HPP
