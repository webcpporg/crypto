// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_HEX_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_HEX_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {

/** The bytes a string of hex digits writes, two per byte; a test's vectors are well formed. */
inline std::vector<std::uint8_t> from_hex(std::string_view hex) {
    auto const digit = [](char c) -> std::uint8_t {
        auto const lower = static_cast<unsigned char>(static_cast<unsigned char>(c) | 0x20U);
        return static_cast<std::uint8_t>(c <= '9' ? c - '0' : lower - 'a' + 10);
    };
    std::vector<std::uint8_t> bytes(hex.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        auto const high = static_cast<std::uint8_t>(digit(hex[2 * i]) << 4U);
        bytes[i] = static_cast<std::uint8_t>(high | digit(hex[(2 * i) + 1]));
    }
    return bytes;
}

/**
 * Not constexpr: a `hex<N>` whose digits reach it is not a constant expression, so a malformed
 * vector stops the compile where it is written.
 */
inline void malformed_hex() noexcept {}

/**
 * The `N` bytes a string of `2 * N` hex digits writes, decoded at compile time: a test's
 * constant vectors, `inline constexpr auto key = hex<32>("...")`. Digits of another count, or a
 * character that is not a hex digit, stop the compile.
 *
 * @tparam N The number of bytes.
 * @param digits Hex digits, either case.
 * @return The bytes.
 */
template <std::size_t N>
consteval std::array<std::uint8_t, N> hex(std::string_view digits) {
    if (digits.size() != 2 * N) {
        malformed_hex();
    }
    auto const digit = [](char c) -> std::uint8_t {
        if (c >= '0' && c <= '9') {
            return static_cast<std::uint8_t>(c - '0');
        }
        if (c >= 'a' && c <= 'f') {
            return static_cast<std::uint8_t>(c - 'a' + 10);
        }
        if (c >= 'A' && c <= 'F') {
            return static_cast<std::uint8_t>(c - 'A' + 10);
        }
        malformed_hex();
        return 0;
    };
    std::array<std::uint8_t, N> bytes{};
    for (std::size_t i = 0; i < N; ++i) {
        auto const high = static_cast<std::uint8_t>(digit(digits[2 * i]) << 4U);
        bytes[i] = static_cast<std::uint8_t>(high | digit(digits[(2 * i) + 1]));
    }
    return bytes;
}

/** Lower-case hex of bytes, for a failure's message. */
inline std::string to_hex(std::span<std::uint8_t const> bytes) {
    static constexpr std::string_view digits = "0123456789abcdef";
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (std::uint8_t const b : bytes) {
        hex += digits[b >> 4U];
        hex += digits[b & 15U];
    }
    return hex;
}

}  // namespace webcpp::test

#endif
