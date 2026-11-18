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

// Ed25519 and Ed25519ph: libsodium, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::ed25519>, backends::sodium>);
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519_SODIUM
#error "curves/ed25519.hpp is told to include another header than libsodium's"
#endif
static_assert(crypto::detail::supported<families::ed25519, families::ed25519,
                                        crypto::default_backend_t<families::ed25519>>);
static_assert(crypto::detail::supported<families::ed25519, crypto::tags::ed25519ph,
                                        crypto::default_backend_t<families::ed25519>>);

// X25519: libsodium, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::x25519>, backends::sodium>);
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_X25519_SODIUM
#error "curves/x25519.hpp is told to include another header than libsodium's"
#endif
static_assert(crypto::detail::supported<families::x25519, families::x25519,
                                        crypto::default_backend_t<families::x25519>>);

// PEM: libsodium, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::pem>, backends::sodium>);
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_PEM_SODIUM
#error "pem.hpp is told to include another header than libsodium's"
#endif
static_assert(crypto::detail::supported<families::pem, families::pem,
                                        crypto::default_backend_t<families::pem>>);

// The three ChaCha20-Poly1305 AEADs: libsodium, the only backend, on every target (the owner's
// answer Q4).
static_assert(
    std::is_same_v<crypto::default_backend_t<families::chacha20_poly1305>, backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<families::chacha20_poly1305_original>,
                             backends::sodium>);
static_assert(
    std::is_same_v<crypto::default_backend_t<families::xchacha20_poly1305>, backends::sodium>);
static_assert(crypto::detail::supported<families::chacha20_poly1305, families::chacha20_poly1305,
                                        backends::sodium>);
static_assert(crypto::detail::supported<families::chacha20_poly1305_original,
                                        families::chacha20_poly1305_original, backends::sodium>);
static_assert(crypto::detail::supported<families::xchacha20_poly1305, families::xchacha20_poly1305,
                                        backends::sodium>);
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_CHACHA20_POLY1305_SODIUM) ||          \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_CHACHA20_POLY1305_ORIGINAL_SODIUM) || \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_XCHACHA20_POLY1305_SODIUM)
#error "chacha20_poly1305.hpp is not told to include libsodium's header"
#endif

// The secret boxes, the boxes and the sealed boxes: libsodium, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::secretbox_xsalsa20poly1305>,
                             backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<families::secretbox_xchacha20poly1305>,
                             backends::sodium>);
static_assert(
    std::is_same_v<crypto::default_backend_t<families::box_xsalsa20poly1305>, backends::sodium>);
static_assert(
    std::is_same_v<crypto::default_backend_t<families::box_xchacha20poly1305>, backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<families::sealed_box>, backends::sodium>);
static_assert(crypto::detail::supported<families::secretbox_xsalsa20poly1305,
                                        families::secretbox_xsalsa20poly1305, backends::sodium>);
static_assert(crypto::detail::supported<families::secretbox_xchacha20poly1305,
                                        families::secretbox_xchacha20poly1305, backends::sodium>);
static_assert(crypto::detail::supported<families::box_xsalsa20poly1305,
                                        families::box_xsalsa20poly1305, backends::sodium>);
static_assert(crypto::detail::supported<families::box_xchacha20poly1305,
                                        families::box_xchacha20poly1305, backends::sodium>);
static_assert(
    crypto::detail::supported<families::sealed_box, families::sealed_box, backends::sodium>);
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XSALSA20POLY1305_SODIUM) ||  \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XCHACHA20POLY1305_SODIUM) || \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BOX_XSALSA20POLY1305_SODIUM) ||        \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_BOX_XCHACHA20POLY1305_SODIUM) ||       \
    !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SEALED_BOX_SODIUM)
#error "secretbox.hpp, box.hpp and sealed_box.hpp are not told to include libsodium's header"
#endif
