// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `chacha20_poly1305`, `chacha20_poly1305_original` and `xchacha20_poly1305`, the
 ChaCha20-Poly1305 AEADs of `aead`, each a `secret_key_encryption::aead::cipher` (design D5) on
 its family's default backend unless the type names another: libsodium on every target, whose
 header it includes when the program links it (`default_backend_t`). A program that uses them
 without linking the default stops where it calls them, with the Jamfile line that links it.
 `ciphers/aead.hpp`, which it includes, brings their free forms, `secret_key_encryption::aead::seal`
 and `open`.

 @see "ChaCha20-Poly1305", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_CHACHA20_POLY1305_HPP
#define WEBCPP_CRYPTO_CIPHERS_CHACHA20_POLY1305_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/detail/defaults.hpp>

#if (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_CHACHA20_POLY1305_SODIUM) ||          \
     defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_CHACHA20_POLY1305_ORIGINAL_SODIUM) || \
     defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_XCHACHA20_POLY1305_SODIUM)) &&        \
    defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

namespace webcpp::crypto::ciphers {

/**
 * RFC 8439's ChaCha20-Poly1305: a 32-byte key, a 12-byte nonce, a 16-byte tag.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::chacha20_poly1305>>
using chacha20_poly1305 = aead<families::chacha20_poly1305, Backend>;

/**
 * The original ChaCha20-Poly1305: a 32-byte key, an 8-byte nonce, a 16-byte tag.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::chacha20_poly1305_original>>
using chacha20_poly1305_original = aead<families::chacha20_poly1305_original, Backend>;

/**
 * XChaCha20-Poly1305: a 32-byte key, a 24-byte nonce safe to draw at random, a 16-byte tag.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::xchacha20_poly1305>>
using xchacha20_poly1305 = aead<families::xchacha20_poly1305, Backend>;

// Each is a one-shot AEAD, which seals no message in pieces (design D5's table).
static_assert(
    secret_key_encryption::aead::cipher<chacha20_poly1305<detail::concept_check_backend>>);
static_assert(
    secret_key_encryption::aead::cipher<chacha20_poly1305_original<detail::concept_check_backend>>);
static_assert(
    secret_key_encryption::aead::cipher<xchacha20_poly1305<detail::concept_check_backend>>);
static_assert(!secret_key_encryption::aead::streaming_cipher<
              chacha20_poly1305<detail::concept_check_backend>>);

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_CHACHA20_POLY1305_HPP
