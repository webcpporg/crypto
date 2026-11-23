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

// The AES block cipher (design D3): natively OpenSSL, whatever is linked; on WebAssembly ctaes,
// which aes256<> names apart from AES-GCM's default.
#ifdef WEBCPP_CRYPTO_WEBASSEMBLY
using block_expected = backends::ctaes;
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_CTAES) || \
    defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_OPENSSL)
#error "aes_block.hpp is told to include another header than ctaes's"
#endif
#else
using block_expected = backends::openssl;
#if !defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_OPENSSL) || \
    defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_AES_BLOCK_CTAES)
#error "aes_block.hpp is told to include another header than OpenSSL's"
#endif
#endif
static_assert(std::is_same_v<crypto::default_backend_t<families::aes_block>, block_expected>);
static_assert(crypto::detail::supported<families::aes_block, crypto::tags::aes256, block_expected>);

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

// crypto_kx: libsodium, the only backend, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::kx>, backends::sodium>);
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_KX_SODIUM
#error "key_exchange/kx.hpp is told to include another header than libsodium's"
#endif
static_assert(
    crypto::detail::supported<families::kx, families::kx, crypto::default_backend_t<families::kx>>);

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

// P-256: BearSSL, the one backend of the P-curves, on every target.
static_assert(std::is_same_v<crypto::default_backend_t<families::p256>, backends::bearssl>);
#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULT_P256_BEARSSL
#error "curves/p256.hpp is told to include another header than BearSSL's"
#endif
static_assert(crypto::detail::supported<families::p256, families::p256,
                                        crypto::default_backend_t<families::p256>>);

// secp256k1's modules, each a family of its own: libsecp256k1, the only backend, on every target.
static_assert(
    std::is_same_v<crypto::default_backend_t<families::secp256k1_ellswift>, backends::secp256k1>);
static_assert(
    std::is_same_v<crypto::default_backend_t<families::secp256k1_musig>, backends::secp256k1>);
static_assert(std::is_same_v<crypto::default_backend_t<families::secp256k1_silent_payments>,
                             backends::secp256k1>);
static_assert(crypto::detail::supported<families::secp256k1_ellswift, families::secp256k1_ellswift,
                                        backends::secp256k1>);
static_assert(crypto::detail::supported<families::secp256k1_musig, families::secp256k1_musig,
                                        backends::secp256k1>);
static_assert(crypto::detail::supported<families::secp256k1_silent_payments,
                                        families::secp256k1_silent_payments, backends::secp256k1>);
