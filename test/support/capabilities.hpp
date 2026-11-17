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
 * Makes an algorithm, through the type a program names, from a key whose bytes are all 1: a
 * cell the capability table marks present whose engine is missing fails to compile here. The
 * type names its family and its algorithm as the table does, and `supports_v` says that the
 * backend has it.
 *
 * @tparam Algorithm The type a program names, on `Backend`.
 * @tparam Family Its family's tag.
 * @tparam Name Its algorithm's tag.
 * @tparam Backend Its backend.
 * @return Whether `make` succeeded.
 */
template <class Algorithm, class Family, class Name, class Backend>
[[nodiscard]] bool made() {
    static_assert(std::is_same_v<typename Algorithm::family_type, Family>);
    static_assert(std::is_same_v<typename Algorithm::name_type, Name>);
    static_assert(webcpp::crypto::supports_v<Algorithm, Backend>);
    std::array<std::uint8_t, key_size_of<Algorithm>()> key_bytes{};
    key_bytes.fill(1);
    return Algorithm::make(key_bytes).has_value();
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_CAPABILITIES_HPP
