// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_CAPABILITIES_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_CAPABILITIES_HPP

#include <webcpp/crypto/supports.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

namespace webcpp::test {

/** The size of the key an algorithm's `make` takes: its `key_size`, else a secret key's 32. */
template <class Algorithm>
constexpr std::size_t key_size_of() {
    if constexpr (requires { Algorithm::key_size; }) {
        return Algorithm::key_size;
    } else {
        return 32;
    }
}

/**
 * Makes an algorithm, through the type a program names, from a key whose bytes are all 1, or,
 * for one made of a secret key and a peer's public key (a box), from that key twice, or, for
 * one keyed by no key of its own (Ed25519ph's signer), begins it, or, for sealed boxes, seals
 * an empty message to that key as a public key, or, for PEM, armours that key as a public key's
 * DER, or, for one of free functions alone (X25519), gives that key's public key: a cell the
 * capability
 * table marks present whose engine is missing fails to compile here. The type names its family
 * and its algorithm as the table does, and `supports_v` says that the backend has it.
 *
 * @tparam Algorithm The type a program names, on `Backend`.
 * @tparam Family Its family's tag.
 * @tparam Name Its algorithm's tag.
 * @tparam Backend Its backend.
 * @return Whether `make`, `begin`, `seal`, `armour` or `public_key` succeeded.
 */
template <class Algorithm, class Family, class Name, class Backend>
[[nodiscard]] bool made() {
    static_assert(std::is_same_v<typename Algorithm::family_type, Family>);
    static_assert(std::is_same_v<typename Algorithm::name_type, Name>);
    static_assert(webcpp::crypto::supports_v<Algorithm, Backend>);
    std::array<std::uint8_t, key_size_of<Algorithm>()> key_bytes{};
    key_bytes.fill(1);
    if constexpr (requires { Algorithm::begin(); }) {
        return Algorithm::begin().has_value();
    } else if constexpr (requires { Algorithm::make(key_bytes); }) {
        return Algorithm::make(key_bytes).has_value();
    } else if constexpr (requires { Algorithm::make(key_bytes, key_bytes); }) {
        return Algorithm::make(key_bytes, key_bytes).has_value();
    } else if constexpr (requires { Algorithm::overhead; }) {
        std::array<std::uint8_t, Algorithm::overhead> sealed{};
        return Algorithm::seal(key_bytes, {}, sealed).has_value();
    } else if constexpr (requires { Algorithm::armour("", key_bytes, std::span<char>{}); }) {
        std::array<char, 128> text{};
        return Algorithm::armour("PUBLIC KEY", key_bytes, text).has_value();
    } else {
        return Algorithm::public_key(key_bytes).has_value();
    }
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_CAPABILITIES_HPP
