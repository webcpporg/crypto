// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `aes128_gcm` and `aes256_gcm` on the default backend, whose header it includes: natively
 OpenSSL when it is linked, else BearSSL; on WebAssembly BearSSL, unless
 `WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL` selects OpenSSL on wasip2 or wasip3 (spec section 5).

 On MSVC, wasip2 and wasip3 the source-built OpenSSL is compiled without assembly: AES is
 table-driven, GHASH is 4-bit tables, there is no AES-NI, and none of it is constant time.
 On MSVC the default follows the spec all the same, so a program that links OpenSSL there
 gets that build. A program that wants BearSSL on those targets defines
 `WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL`, or names `gcm<aes256<backends::bearssl>>`.

 The MSVC link-time net (`detect_mismatch`) covers the translation units that include this
 header; a program that names `aes256<>` through `aes.hpp` gets the same choice from
 `config.hpp` but no link-time net.

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_AES256_GCM_HPP
#define WEBCPP_CRYPTO_AES256_GCM_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/gcm.hpp>

#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#else
#include <webcpp/crypto/backends/bearssl.hpp>
#endif

// Two files of one program that choose different defaults name two types aes256_gcm: on
// MSVC the link then fails with LNK2038 on this key (Review Focus 4).
#if defined(_MSC_VER) && defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL)
#pragma detect_mismatch("webcpp_crypto_default_backend", "openssl")
#elif defined(_MSC_VER)
#pragma detect_mismatch("webcpp_crypto_default_backend", "bearssl")
#endif

namespace webcpp::crypto {

/** AES-128-GCM on the default backend. */
using aes128_gcm = gcm<aes128<>>;
/** AES-256-GCM on the default backend. */
using aes256_gcm = gcm<aes256<>>;

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_AES256_GCM_HPP
