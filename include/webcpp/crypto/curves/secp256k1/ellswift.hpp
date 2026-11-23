// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1's ElligatorSwift on libsecp256k1: a public key written as 64 bytes that cannot be
 told from random ones, read back from any 64 bytes, made from a key pair's secret, and the
 x-only key exchange of two such encodings, hashed as BIP 324 hashes it into a `secret<32>`.

 @see "ElligatorSwift: keys that look like noise", in the guide's secp256k1 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_ELLSWIFT_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_ELLSWIFT_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * The refusal of a backend other than libsecp256k1 by the family `families::secp256k1_ellswift`:
 * the functions of `curves/secp256k1/ellswift.hpp`.
 *
 * @tparam Backend The backend named.
 */
template <class Backend>
struct secp256k1_refusal<families::secp256k1_ellswift, Backend, false> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECP256K1_ELLSWIFT(Backend);
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/** The size of an ElligatorSwift encoding: 64 bytes, indistinguishable from random. */
inline constexpr std::size_t ellswift_size = 64;

/** The two sides of `ellswift_xdh` (BIP 324's initiator and responder). */
enum class ellswift_party {
    /** The side whose encoding comes first in the hash: BIP 324's initiator. */
    initiator = 0,
    /** The other side. */
    responder = 1,
};

/**
 * A public key's ElligatorSwift encoding (`secp256k1_ellswift_encode`): one of many, chosen by
 * the randomness, each of which decodes to the key.
 *
 * Tip: `ellswift_create` makes the encoding of a key pair's own key from its secret, which
 * libsecp256k1 recommends over this function.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key.
 * @param randomness_bytes 32 fresh bytes from crypto's random device: the encoding is one of many.
 * @return The 64 bytes.
 */
template <class Backend = default_backend_t<families::secp256k1_ellswift>>
[[nodiscard]] std::array<std::uint8_t, ellswift_size> ellswift_encode(
    public_key const& parsed_key, std::span<std::uint8_t const, 32> randomness_bytes) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_ellswift, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::array<std::uint8_t, ellswift_size> encoded_key{};
    // libsecp256k1 returns 1 always: every valid point has encodings.
    static_cast<void>(secp256k1_ellswift_encode(
        secp256k1_context_static, encoded_key.data(),
        &webcpp::crypto::detail::secp256k1_access::point(parsed_key), randomness_bytes.data()));
    return encoded_key;
}

/**
 * The public key of any 64 bytes (`secp256k1_ellswift_decode`): every input decodes.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param encoded_key The 64 bytes, as received.
 * @return The key.
 */
template <class Backend = default_backend_t<families::secp256k1_ellswift>>
[[nodiscard]] public_key ellswift_decode(
    std::span<std::uint8_t const, ellswift_size> encoded_key) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_ellswift, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    public_key decoded_key = access::make_public_key();
    // libsecp256k1 returns 1 always: ElligatorSwift maps every 64 bytes to a point.
    static_cast<void>(secp256k1_ellswift_decode(secp256k1_context_static,
                                                &access::point(decoded_key), encoded_key.data()));
    return decoded_key;
}

/**
 * The encoding of a key pair's public key, made from its secret with the key pair's context
 * (`secp256k1_ellswift_create`), so that the public key is never computed apart.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @param key_pair The key pair.
 * @param randomness_bytes 32 fresh bytes from crypto's random device, mixed with the secret into
 * the choice of the encoding.
 * @return 64 bytes; `invalid_state` moved from; `backend_failure`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, ellswift_size>> ellswift_create(
    basic_keypair<Backend> const& key_pair,
    std::span<std::uint8_t const, 32> randomness_bytes) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_ellswift, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(key_pair)) {
        return error::invalid_state;
    }
    webcpp::crypto::detail::secp256k1_secret native_secret;
    secp256k1_keypair_sec(access::context(key_pair), native_secret.bytes.data(),
                          &access::pair(key_pair));
    std::array<std::uint8_t, ellswift_size> encoded_key{};
    // The key pair's secret is valid: libsecp256k1 refuses only one that is not.
    if (!webcpp::crypto::detail::secp256k1_accepted(
            secp256k1_ellswift_create(access::context(key_pair), encoded_key.data(),
                                      native_secret.bytes.data(), randomness_bytes.data()))) {
        return error::backend_failure;
    }
    return encoded_key;
}

/**
 * The shared secret of an ElligatorSwift key exchange, hashed as BIP 324 hashes it
 * (`secp256k1_ellswift_xdh` with `secp256k1_ellswift_xdh_hash_function_bip324`): a tagged
 * hash of both encodings and the shared point's x coordinate.
 *
 * Tip: both sides pass the two encodings in the same order, the initiator's first, and each
 * names its own party; the secret is input to the protocol's key schedule, never a key itself.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @param key_pair The key pair, whose encoding is `our_party`'s.
 * @param initiator_encoding The initiator's 64 bytes, as sent.
 * @param responder_encoding The responder's 64 bytes, as sent.
 * @param our_party Which of the two this key pair is.
 * @return 32 secret bytes; `invalid_state` moved from; `backend_failure`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<secret<32>> ellswift_xdh(
    basic_keypair<Backend> const& key_pair,
    std::span<std::uint8_t const, ellswift_size> initiator_encoding,
    std::span<std::uint8_t const, ellswift_size> responder_encoding,
    ellswift_party our_party) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_ellswift, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(key_pair)) {
        return error::invalid_state;
    }
    webcpp::crypto::detail::secp256k1_secret native_secret;
    secp256k1_keypair_sec(access::context(key_pair), native_secret.bytes.data(),
                          &access::pair(key_pair));
    secret<32> shared_secret;
    // The secret is valid and BIP 324's hash never fails: libsecp256k1 returns 1.
    if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_ellswift_xdh(
            access::context(key_pair), shared_secret.writable().data(), initiator_encoding.data(),
            responder_encoding.data(), native_secret.bytes.data(), static_cast<int>(our_party),
            secp256k1_ellswift_xdh_hash_function_bip324, nullptr))) {
        return error::backend_failure;
    }
    return shared_secret;
}

}  // namespace webcpp::crypto::curves::secp256k1

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_ELLSWIFT_HPP
