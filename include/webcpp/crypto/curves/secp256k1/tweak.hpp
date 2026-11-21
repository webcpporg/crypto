// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1's tweaks, negation and combination of secret and public keys on libsecp256k1: a
 secret key plus or times a tweak, the same on its public key, the negation of either, and the
 sum of public keys. Each tweaked or negated secret key is a `secret<32>`.

 @see "Tweaks, negation and combination", in the guide's secp256k1 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_TWEAK_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_TWEAK_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/** The function libsecp256k1 runs on a secret key and a tweak: `secp256k1_ec_seckey_tweak_*`. */
using secp256k1_seckey_tweak = int (*)(secp256k1_context const*, unsigned char*,
                                       unsigned char const*);

/** The function libsecp256k1 runs on a public key and a tweak: `secp256k1_ec_pubkey_tweak_*`. */
using secp256k1_pubkey_tweak = int (*)(secp256k1_context const*, secp256k1_pubkey*,
                                       unsigned char const*);

/**
 * A secret key tweaked by libsecp256k1, computed in a wiped copy of the key and moved into the
 * secret returned.
 *
 * @param secret_key The 32-byte secret key.
 * @param tweak_bytes The 32-byte tweak, or null for a negation.
 * @param tweak_function libsecp256k1's tweak, used when `tweak_bytes` is not null.
 * @return The secret; `invalid_secret_key` for a secret key zero or not below the group order,
 * then for a tweak not below it or a result of zero.
 */
[[nodiscard]] inline boost::system::result<secret<32>> secp256k1_tweaked_secret(
    std::span<std::uint8_t const, 32> secret_key, unsigned char const* tweak_bytes,
    secp256k1_seckey_tweak tweak_function) noexcept {
    // The key is checked first, so that a refusal names the input that was wrong.
    if (!secp256k1_accepted(
            secp256k1_ec_seckey_verify(secp256k1_context_static, secret_key.data()))) {
        return error::invalid_secret_key;
    }
    secp256k1_secret working_copy;
    std::ranges::copy(secret_key, working_copy.bytes.begin());
    int const status =
        tweak_bytes == nullptr
            ? secp256k1_ec_seckey_negate(secp256k1_context_static, working_copy.bytes.data())
            : tweak_function(secp256k1_context_static, working_copy.bytes.data(), tweak_bytes);
    if (!secp256k1_accepted(status)) {
        return error::invalid_secret_key;
    }
    secret<32> tweaked_secret;
    std::ranges::copy(working_copy.bytes, tweaked_secret.writable().begin());
    return tweaked_secret;
}

/**
 * A public key tweaked by libsecp256k1 on the static context.
 *
 * @param parsed_key The key, valid.
 * @param tweak_bytes The 32-byte tweak.
 * @param tweak_function libsecp256k1's tweak.
 * @return The key; `invalid_secret_key` for a tweak not below the group order, a zero
 * multiplier, or a result at infinity.
 */
[[nodiscard]] inline boost::system::result<curves::secp256k1::public_key> secp256k1_tweaked_key(
    curves::secp256k1::public_key const& parsed_key, std::span<std::uint8_t const, 32> tweak_bytes,
    secp256k1_pubkey_tweak tweak_function) noexcept {
    curves::secp256k1::public_key tweaked_key = parsed_key;
    if (tweak_function(secp256k1_context_static, &secp256k1_access::point(tweaked_key),
                       tweak_bytes.data()) == 0) {
        return error::invalid_secret_key;
    }
    return tweaked_key;
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/**
 * The workspace `pubkey_combine` needs for `key_count` keys, in bytes.
 *
 * @param key_count The number of keys combined.
 * @return One pointer per key and one `alignof(std::max_align_t)` of padding.
 */
[[nodiscard]] constexpr std::size_t combine_workspace_size(std::size_t key_count) noexcept {
    return (key_count * sizeof(secp256k1_pubkey const*)) + alignof(std::max_align_t);
}

/**
 * A secret key plus a tweak modulo the group order (`secp256k1_ec_seckey_tweak_add`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param secret_key The 32-byte secret key.
 * @param tweak_bytes The 32-byte tweak, a big-endian scalar.
 * @return The tweaked secret key; `invalid_secret_key` for a secret key zero or not below the
 * group order, a tweak not below it, or a sum of zero.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<secret<32>> seckey_tweak_add(
    std::span<std::uint8_t const, 32> secret_key,
    std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    return webcpp::crypto::detail::secp256k1_tweaked_secret(secret_key, tweak_bytes.data(),
                                                            secp256k1_ec_seckey_tweak_add);
}

/**
 * A secret key times a tweak modulo the group order (`secp256k1_ec_seckey_tweak_mul`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param secret_key The 32-byte secret key.
 * @param tweak_bytes The 32-byte tweak, a big-endian scalar.
 * @return The tweaked secret key; `invalid_secret_key` for a secret key zero or not below the
 * group order, or a tweak that is zero or not below it.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<secret<32>> seckey_tweak_mul(
    std::span<std::uint8_t const, 32> secret_key,
    std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    return webcpp::crypto::detail::secp256k1_tweaked_secret(secret_key, tweak_bytes.data(),
                                                            secp256k1_ec_seckey_tweak_mul);
}

/**
 * The group order minus a secret key (`secp256k1_ec_seckey_negate`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param secret_key The 32-byte secret key.
 * @return The negated secret key; `invalid_secret_key` for a secret key zero or not below the
 * group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<secret<32>> seckey_negate(
    std::span<std::uint8_t const, 32> secret_key) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    return webcpp::crypto::detail::secp256k1_tweaked_secret(secret_key, nullptr, nullptr);
}

/**
 * A public key P plus t times the generator (`secp256k1_ec_pubkey_tweak_add`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key P.
 * @param tweak_bytes The 32-byte tweak t, a big-endian scalar.
 * @return The tweaked key; `invalid_secret_key` for a tweak not below the group order, or a
 * sum at infinity.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> pubkey_tweak_add(
    public_key const& parsed_key, std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    return webcpp::crypto::detail::secp256k1_tweaked_key(parsed_key, tweak_bytes,
                                                         secp256k1_ec_pubkey_tweak_add);
}

/**
 * A public key P times t (`secp256k1_ec_pubkey_tweak_mul`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key P.
 * @param tweak_bytes The 32-byte tweak t, a big-endian scalar.
 * @return The tweaked key; `invalid_secret_key` for a tweak that is zero or not below the
 * group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> pubkey_tweak_mul(
    public_key const& parsed_key, std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    return webcpp::crypto::detail::secp256k1_tweaked_key(parsed_key, tweak_bytes,
                                                         secp256k1_ec_pubkey_tweak_mul);
}

/**
 * The negation -P of a public key (`secp256k1_ec_pubkey_negate`), which never fails.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key P.
 * @return -P, the public key of the negated secret key.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] public_key pubkey_negate(public_key const& parsed_key) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    public_key negated_key = parsed_key;
    // A valid point always negates: libsecp256k1 returns 1.
    static_cast<void>(secp256k1_ec_pubkey_negate(
        secp256k1_context_static, &webcpp::crypto::detail::secp256k1_access::point(negated_key)));
    return negated_key;
}

/**
 * The sum of public keys (`secp256k1_ec_pubkey_combine`), in a workspace the caller lends for
 * libsecp256k1's array of pointers.
 *
 * Tip: the sum of keys an attacker chooses is not a multisignature's key: the attacker picks
 * its key as another's negation plus its own (a rogue key), and the sum is its alone. MuSig2
 * aggregates keys safely.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_keys The keys, at least one.
 * @param pointer_space At least `combine_workspace_size(parsed_keys.size())` bytes; zero when
 * the function returns, whatever it returns.
 * @return The sum; `invalid_input_size` for no keys or a short workspace; `invalid_public_key`
 * for a sum at infinity.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> pubkey_combine(
    std::span<public_key const> parsed_keys, workspace pointer_space) noexcept {
    detail::timing_guard const timing;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace on every return, a refusal's included.
    webcpp::crypto::detail::secp256k1_workspace carver(pointer_space);
    // libsecp256k1 checks the count with ARG_CHECK, whose callback aborts: refused first here.
    if (parsed_keys.empty() || pointer_space.size() < combine_workspace_size(parsed_keys.size())) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto* const key_pointers = carver.take<secp256k1_pubkey const*>(parsed_keys.size());
    if (key_pointers == nullptr) {
        return error::invalid_input_size;
    }
    for (std::size_t key_index = 0; key_index < parsed_keys.size(); ++key_index) {
        key_pointers[key_index] = &access::point(parsed_keys[key_index]);
    }
    public_key combined_key = access::make_public_key();
    if (secp256k1_ec_pubkey_combine(secp256k1_context_static, &access::point(combined_key),
                                    key_pointers, parsed_keys.size()) == 0) {
        return error::invalid_public_key;
    }
    return combined_key;
}

}  // namespace webcpp::crypto::curves::secp256k1

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_TWEAK_HPP
