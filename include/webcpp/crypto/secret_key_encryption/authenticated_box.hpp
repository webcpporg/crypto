// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The boxes' contract (design D5, R21): the concept `secret_key_encryption::authenticated_box`,
 authenticated encryption in place without associated data, what NaCl's and libsodium's secret
 boxes and crypto_boxes are; and the free synchronous forms of its members, the box forms
 `secret_key_encryption::seal(box, nonce, data)` and
 `secret_key_encryption::open(box, nonce, data, tag)`, for a secret box and a crypto_box alike.

 The concept lives beside the secret box, in `secret_key_encryption`; crypto_box, in
 `public_key_encryption`, satisfies it too, and is sealed by `secret_key_encryption::seal` named
 in full, or by its member: no free `seal` or `open` exists in `crypto::` nor in
 `public_key_encryption`. A box given to the AEAD forms, `secret_key_encryption::aead::seal` or
 `open`, which take associated data, stops the build with a message naming the box forms. It
 needs no backend.

 @see "The box forms: `secret_key_encryption::seal` and `open`", in the guide.
*/
#ifndef WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AUTHENTICATED_BOX_HPP
#define WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AUTHENTICATED_BOX_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret_key_encryption/aead.hpp>  // the AEAD forms a box is refused by

#include <boost/system/result.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::secret_key_encryption {

/**
 * Whether `Box` is an authenticated box (design D5, R21), encryption in place without associated
 * data.
 *
 * The tag is apart. `secret_key_encryption::secretbox`, `secretbox_xchacha20poly1305`,
 * `public_key_encryption::box` and `box_xchacha20poly1305` are:
 * - `Box::key_size`, `Box::nonce_size` and `Box::tag_size`, sizes in bytes, and
 *   `typename Box::result_type`, the tag;
 * - `keyed_box.seal(nonce_bytes, data_bytes)` seals `data_bytes` in place and gives
 *   `result<result_type>`, the tag;
 * - `keyed_box.open(nonce_bytes, data_bytes, tag_bytes)` opens `data_bytes` in place and gives
 *   `result<void>`, `data_bytes` zeroed when it fails.
 *
 * The factory is not part of it: a secret box is made by `from_key`, a crypto_box by `from_keys`
 * from two X25519 keys.
 *
 * @tparam Box A type, without its reference and qualifiers.
 */
template <class Box>
concept authenticated_box =
    requires(Box& keyed_box, std::span<std::uint8_t const> nonce_bytes,
             std::span<std::uint8_t>& data_bytes, std::span<std::uint8_t const> tag_bytes) {
        { Box::key_size } -> std::convertible_to<std::size_t>;
        { Box::nonce_size } -> std::convertible_to<std::size_t>;
        { Box::tag_size } -> std::convertible_to<std::size_t>;
        typename Box::result_type;
        {
            keyed_box.seal(nonce_bytes, data_bytes)
        } -> std::same_as<boost::system::result<typename Box::result_type>>;
        {
            keyed_box.open(nonce_bytes, data_bytes, tag_bytes)
        } -> std::same_as<boost::system::result<void>>;
    };

/**
 * Seals a message in place, `keyed_box.seal(nonce_bytes, data_bytes)`: the free form of the box's
 * own `seal`, which it calls, with its results and its errors.
 *
 * @tparam Box An `authenticated_box`: a secret box or a crypto_box.
 * @param keyed_box The keyed box.
 * @param nonce_bytes The nonce, never reused under this key.
 * @param data_bytes The message, the ciphertext after.
 * @return What `keyed_box.seal` returns: the tag, or its error.
 */
template <authenticated_box Box>
[[nodiscard]] boost::system::result<typename Box::result_type> seal(
    Box& keyed_box, std::span<std::uint8_t const> nonce_bytes,
    std::span<std::uint8_t> data_bytes) noexcept(noexcept(keyed_box.seal(nonce_bytes,
                                                                         data_bytes))) {
    detail::timing_guard const timing_scope;
    return keyed_box.seal(nonce_bytes, data_bytes);
}

/**
 * Opens a message in place, `keyed_box.open(nonce_bytes, data_bytes, tag_bytes)`: the free form of
 * the box's own `open`, which it calls, with its results and its errors.
 *
 * @tparam Box An `authenticated_box`: a secret box or a crypto_box.
 * @param keyed_box The keyed box.
 * @param nonce_bytes The nonce of the seal.
 * @param data_bytes The ciphertext, the plaintext after.
 * @param tag_bytes The seal's tag.
 * @return What `keyed_box.open` returns: nothing, or its error (`authentication_failed`, which
 * zeroes `data_bytes`).
 */
template <authenticated_box Box>
[[nodiscard]] boost::system::result<void> open(
    Box& keyed_box, std::span<std::uint8_t const> nonce_bytes, std::span<std::uint8_t> data_bytes,
    std::span<std::uint8_t const> tag_bytes) noexcept(noexcept(keyed_box.open(nonce_bytes,
                                                                              data_bytes,
                                                                              tag_bytes))) {
    detail::timing_guard const timing_scope;
    return keyed_box.open(nonce_bytes, data_bytes, tag_bytes);
}

}  // namespace webcpp::crypto::secret_key_encryption

namespace webcpp::crypto::secret_key_encryption::aead {

/**
 * A box given to the AEAD form of `seal`, which takes associated data: refused, naming the box
 * form.
 *
 * Never called: the refusal stops the build where it is instantiated.
 *
 * @tparam Box An `authenticated_box`, which is no `cipher`.
 * @return Never returns to a program: it does not compile.
 */
template <authenticated_box Box>
[[nodiscard]] boost::system::result<typename Box::result_type> seal(
    Box& /*keyed_box*/, std::span<std::uint8_t const> /*nonce_bytes*/,
    std::span<std::uint8_t const> /*associated_data_bytes*/,
    std::span<std::uint8_t> /*data_bytes*/) noexcept {
    static_assert(detail::dependent_false<Box>,
                  "webcpp::crypto: seal: a secret box or a crypto_box takes no associated data: "
                  "secret_key_encryption::seal(box, nonce, data).");
    return error::backend_failure;
}

/**
 * A box given to the AEAD form of `open`, which takes associated data: refused, naming the box
 * form.
 *
 * Never called: the refusal stops the build where it is instantiated.
 *
 * @tparam Box An `authenticated_box`, which is no `cipher`.
 * @return Never returns to a program: it does not compile.
 */
template <authenticated_box Box>
[[nodiscard]] boost::system::result<void> open(
    Box& /*keyed_box*/, std::span<std::uint8_t const> /*nonce_bytes*/,
    std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> /*data_bytes*/,
    std::span<std::uint8_t const> /*tag_bytes*/) noexcept {
    static_assert(detail::dependent_false<Box>,
                  "webcpp::crypto: open: a secret box or a crypto_box takes no associated data: "
                  "secret_key_encryption::open(box, nonce, data, tag).");
    return error::backend_failure;
}

}  // namespace webcpp::crypto::secret_key_encryption::aead

#endif  // WEBCPP_CRYPTO_SECRET_KEY_ENCRYPTION_AUTHENTICATED_BOX_HPP
