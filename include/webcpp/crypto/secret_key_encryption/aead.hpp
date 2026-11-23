// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The AEAD contract (design D5, D11): the concepts `secret_key_encryption::aead::cipher`, what
 every one-shot AEAD is, and its refinement `streaming_cipher`, an AEAD that also seals and opens
 a message in pieces; and the free synchronous forms of their members (design D9),
 `secret_key_encryption::aead::seal(cipher, nonce, associated_data, data)` and
 `secret_key_encryption::aead::open(cipher, nonce, associated_data, data, tag)`.

 The namespace is named by what the contract is for, encryption under one secret key with
 associated data, as `secret_key_encryption` holds the constructions under one secret key and
 `public_key_encryption` those between key pairs (owner decision 13); the algorithms that satisfy
 it stay in `ciphers` under their names. Every AEAD's header includes this one, so that a
 program that includes `ciphers/chacha20_poly1305.hpp` or `ciphers/gcm.hpp` has its free forms.
 It needs no backend.

 @see "The AEAD contract: `secret_key_encryption::aead`", in the guide.
*/
#ifndef WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AEAD_HPP
#define WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AEAD_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/timing.hpp>

#include <boost/system/result.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * A backend no header specialises, on which a header instantiates its class to check it against
 * its concept with a `static_assert`: no engine is reached, since a concept reads declarations
 * alone, and no backend's specialisation of a state follows the instantiation, which would be
 * ill-formed.
 */
struct concept_check_backend {};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::secret_key_encryption::aead {

/**
 * Whether `Cipher` is a one-shot AEAD (design D5).
 *
 * `ciphers::gcm<Cipher>` and every `ciphers::aead<Family, Backend>`, ChaCha20-Poly1305 in its
 * three nonce sizes, are:
 * - `Cipher::key_size`, `Cipher::nonce_size` and `Cipher::tag_size`, sizes in bytes, and
 *   `typename Cipher::result_type`, the tag;
 * - `Cipher::from_key(key_bytes)` gives `result<Cipher>`;
 * - `keyed_cipher.seal(nonce_bytes, associated_data_bytes, data_bytes)` seals `data_bytes` in
 *   place and gives `result<result_type>`, the tag;
 * - `keyed_cipher.open(nonce_bytes, associated_data_bytes, data_bytes, tag_bytes)` opens
 *   `data_bytes` in place and gives `result<void>`, `data_bytes` zeroed when it fails.
 *
 * A secret box or a crypto_box takes no associated data: it is a
 * `secret_key_encryption::authenticated_box`, never a `cipher`.
 *
 * @tparam Cipher A type, without its reference and qualifiers.
 */
template <class Cipher>
concept cipher =
    requires(Cipher& keyed_cipher, std::span<std::uint8_t const>& key_bytes,
             std::span<std::uint8_t const> const& nonce_bytes,
             std::span<std::uint8_t const> const& associated_data_bytes,
             std::span<std::uint8_t>& data_bytes, std::span<std::uint8_t const> tag_bytes) {
        { Cipher::key_size } -> std::convertible_to<std::size_t>;
        { Cipher::nonce_size } -> std::convertible_to<std::size_t>;
        { Cipher::tag_size } -> std::convertible_to<std::size_t>;
        typename Cipher::result_type;
        { Cipher::from_key(key_bytes) } -> std::same_as<boost::system::result<Cipher>>;
        {
            keyed_cipher.seal(nonce_bytes, associated_data_bytes, data_bytes)
        } -> std::same_as<boost::system::result<typename Cipher::result_type>>;
        {
            keyed_cipher.open(nonce_bytes, associated_data_bytes, data_bytes, tag_bytes)
        } -> std::same_as<boost::system::result<void>>;
    };

/**
 * Whether `Cipher` is a `cipher` that also seals and opens a message in pieces (design D5).
 *
 * `ciphers::gcm<Cipher>` is, with these members:
 * - `begin_seal(nonce_bytes, associated_data_bytes)`, then `update(data_piece)` for each piece,
 *   sealed in place, then `result()`, the tag;
 * - `begin_open(nonce_bytes, associated_data_bytes)`, then `authenticate(ciphertext_piece)` for
 *   each piece and `verify(tag_bytes)`, then `decrypt(data_piece)` for the same pieces and
 *   `end_open()`, so that no plaintext is given before the tag matched.
 *
 * Each gives `result<void>`, `result()` the tag, `result<result_type>`.
 *
 * @tparam Cipher A type, without its reference and qualifiers.
 */
template <class Cipher>
concept streaming_cipher =
    cipher<Cipher> &&
    requires(Cipher& keyed_cipher, std::span<std::uint8_t const> const& nonce_bytes,
             std::span<std::uint8_t const> const& associated_data_bytes,
             std::span<std::uint8_t> data_piece, std::span<std::uint8_t const> ciphertext_piece,
             std::span<std::uint8_t const> tag_bytes) {
        {
            keyed_cipher.begin_seal(nonce_bytes, associated_data_bytes)
        } -> std::same_as<boost::system::result<void>>;
        { keyed_cipher.update(data_piece) } -> std::same_as<boost::system::result<void>>;
        {
            keyed_cipher.result()
        } -> std::same_as<boost::system::result<typename Cipher::result_type>>;
        {
            keyed_cipher.begin_open(nonce_bytes, associated_data_bytes)
        } -> std::same_as<boost::system::result<void>>;
        {
            keyed_cipher.authenticate(ciphertext_piece)
        } -> std::same_as<boost::system::result<void>>;
        { keyed_cipher.decrypt(data_piece) } -> std::same_as<boost::system::result<void>>;
        { keyed_cipher.verify(tag_bytes) } -> std::same_as<boost::system::result<void>>;
        { keyed_cipher.end_open() } -> std::same_as<boost::system::result<void>>;
    };

/**
 * Seals a message in place,
 * `keyed_cipher.seal(nonce_bytes, associated_data_bytes, data_bytes)`: the free form of the
 * AEAD's own `seal`, which it calls, with its results and its errors.
 *
 * @tparam Cipher A `cipher`: `ciphers::gcm<Cipher>` or `ciphers::aead<Family, Backend>`.
 * @param keyed_cipher The keyed object.
 * @param nonce_bytes The nonce, never reused under this key.
 * @param associated_data_bytes Authenticated, not encrypted.
 * @param data_bytes The message, the ciphertext after.
 * @return What `keyed_cipher.seal` returns: the tag, or its error.
 */
template <cipher Cipher>
[[nodiscard]] boost::system::result<typename Cipher::result_type> seal(
    Cipher& keyed_cipher, std::span<std::uint8_t const> nonce_bytes,
    std::span<std::uint8_t const> associated_data_bytes,
    std::span<std::uint8_t> data_bytes) noexcept(noexcept(keyed_cipher.seal(nonce_bytes,
                                                                            associated_data_bytes,
                                                                            data_bytes))) {
    detail::timing_guard const timing_scope;
    return keyed_cipher.seal(nonce_bytes, associated_data_bytes, data_bytes);
}

/**
 * Opens a message in place,
 * `keyed_cipher.open(nonce_bytes, associated_data_bytes, data_bytes, tag_bytes)`: the free form
 * of the AEAD's own `open`, which it calls, with its results and its errors.
 *
 * @tparam Cipher A `cipher`: `ciphers::gcm<Cipher>` or `ciphers::aead<Family, Backend>`.
 * @param keyed_cipher The keyed object.
 * @param nonce_bytes The nonce of the seal.
 * @param associated_data_bytes The associated data of the seal.
 * @param data_bytes The ciphertext, the plaintext after.
 * @param tag_bytes The seal's tag.
 * @return What `keyed_cipher.open` returns: nothing, or its error (`authentication_failed`,
 * which zeroes `data_bytes`).
 */
template <cipher Cipher>
[[nodiscard]] boost::system::result<void> open(
    Cipher& keyed_cipher, std::span<std::uint8_t const> nonce_bytes,
    std::span<std::uint8_t const> associated_data_bytes, std::span<std::uint8_t> data_bytes,
    std::span<std::uint8_t const>
        tag_bytes) noexcept(noexcept(keyed_cipher.open(nonce_bytes, associated_data_bytes,
                                                       data_bytes, tag_bytes))) {
    detail::timing_guard const timing_scope;
    return keyed_cipher.open(nonce_bytes, associated_data_bytes, data_bytes, tag_bytes);
}

}  // namespace webcpp::crypto::secret_key_encryption::aead

#endif  // WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AEAD_HPP
