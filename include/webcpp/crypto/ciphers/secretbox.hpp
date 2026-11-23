// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `secretbox` and `secretbox_xchacha20poly1305`, NaCl's and libsodium's secret boxes as `aead`s
 without associated data, each on its family's default backend unless the type names another:
 libsodium on every target, whose header it includes when the program links it
 (`default_backend_t`). A program that uses them without linking the default stops where it
 calls them, with the Jamfile line that links it.

 @see "Secret boxes", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CIPHERS_SECRETBOX_HPP
#define WEBCPP_CRYPTO_CIPHERS_SECRETBOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/detail/defaults.hpp>

#if (defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XSALSA20POLY1305_SODIUM) ||   \
     defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_SECRETBOX_XCHACHA20POLY1305_SODIUM)) && \
    defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

namespace webcpp::crypto::ciphers {

/**
 * NaCl's and libsodium's `crypto_secretbox`, XSalsa20-Poly1305: a 32-byte key, a 24-byte nonce
 * safe to draw at random, a 16-byte tag, and no associated data, which `seal` and `open` refuse
 * unless empty (`invalid_input_size`).
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::secretbox_xsalsa20poly1305>>
using secretbox = aead<families::secretbox_xsalsa20poly1305, Backend>;

/**
 * libsodium's `crypto_secretbox_xchacha20poly1305`: the secret box with XChaCha20 in place of
 * XSalsa20, of the same sizes and without associated data.
 *
 * @tparam Backend The backend; the default is the family's.
 */
template <class Backend = default_backend_t<families::secretbox_xchacha20poly1305>>
using secretbox_xchacha20poly1305 = aead<families::secretbox_xchacha20poly1305, Backend>;

}  // namespace webcpp::crypto::ciphers

#endif  // WEBCPP_CRYPTO_CIPHERS_SECRETBOX_HPP
