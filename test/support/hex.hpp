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
        return static_cast<std::uint8_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    };
    std::vector<std::uint8_t> bytes(hex.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>(digit(hex[2 * i]) << 4U | digit(hex[2 * i + 1]));
    }
    return bytes;
}

/** Lower-case hex of bytes, for a failure's message. */
inline std::string to_hex(std::span<std::uint8_t const> bytes) {
    static constexpr std::array<char, 16> digits{'0', '1', '2', '3', '4', '5', '6', '7',
                                                 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
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
