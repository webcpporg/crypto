// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every family's default backend on the target being compiled (design D32): one per family and
// target, whatever the program links and whatever it defines. test/Jamfile builds this file with
// every backend of the target linked, with none, with each alone, and with the defines of the
// profiles and of a per-family override, which version 0.2 does not have; every build asserts
// the same defaults.

#include <webcpp/crypto/detail/defaults.hpp>

#include <type_traits>

namespace crypto = webcpp::crypto;
namespace backends = webcpp::crypto::backends;
namespace families = webcpp::crypto::families;

namespace {

/** Whether `Family` has a default: `default_backend_t<Family>` names a type. */
template <class Family, class = void>
inline constexpr bool has_default = false;

/** A family with a default. */
template <class Family>
inline constexpr bool has_default<Family, std::void_t<crypto::default_backend_t<Family>>> = true;

}  // namespace

// AES-GCM: natively OpenSSL, whatever is linked (the owner's answer Q2); on WebAssembly BearSSL.
#ifdef WEBCPP_CRYPTO_WEBASSEMBLY
using gcm_default = backends::bearssl;
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_BEARSSL) || \
    defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_OPENSSL)
#error "aes256_gcm.hpp is told to include another header than BearSSL's"
#endif
#else
using gcm_default = backends::openssl;
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_OPENSSL) || \
    defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_GCM_BEARSSL)
#error "aes256_gcm.hpp is told to include another header than OpenSSL's"
#endif
#endif
static_assert(std::is_same_v<crypto::default_backend_t<families::gcm>, gcm_default>);
static_assert(std::is_same_v<crypto::default_backend, gcm_default>);
static_assert(crypto::detail::supported<families::gcm, crypto::tags::aes256_gcm, gcm_default>);

// The AES block cipher: none (its aes256<> takes AES-GCM's as its argument).
static_assert(!has_default<families::aes_block>);

// secp256k1: libsecp256k1, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::secp256k1>, backends::secp256k1>);
static_assert(crypto::detail::supported<families::secp256k1, families::secp256k1,
                                        crypto::default_backend_t<families::secp256k1>>);
