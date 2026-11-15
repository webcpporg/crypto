// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Readers the secp256k1 vector tests share (a whole file is test_data.hpp's): a base64url
// string without padding, a scalar normalised to the 32 bytes the secp256k1 API takes, and the
// high-S twin of a compact signature.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_DATA_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_DATA_HPP

#include "hex.hpp"
#include "test_data.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {

/**
 * The bytes of a base64url string without padding (`-` and `_`); any other character ends
 * the test, by name.
 */
inline std::vector<std::uint8_t> from_base64url(std::string_view text) {
    std::vector<std::uint8_t> out;
    std::uint32_t bits = 0;
    int count = 0;
    for (char const c : text) {
        std::uint32_t v = 0;
        if (c >= 'A' && c <= 'Z') {
            v = static_cast<std::uint32_t>(c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            v = static_cast<std::uint32_t>(c - 'a' + 26);
        } else if (c >= '0' && c <= '9') {
            v = static_cast<std::uint32_t>(c - '0' + 52);
        } else if (c == '-') {
            v = 62;
        } else if (c == '_') {
            v = 63;
        } else {
            std::cerr << "not base64url: " << text << '\n';
            std::abort();
        }
        bits = (bits << 6U) | v;
        count += 6;
        if (count >= 8) {
            count -= 8;
            out.push_back(
                static_cast<std::uint8_t>((bits >> static_cast<unsigned>(count)) & 0xFFU));
        }
    }
    // Without padding, 2 or 3 characters of a last group leave 4 or 2 bits over, which a
    // canonical encoding zeroes; 1 character (6 bits over) is never a whole byte.
    if (count >= 6 || (bits & ((1U << static_cast<unsigned>(count)) - 1U)) != 0) {
        std::cerr << "not canonical base64url: " << text << '\n';
        std::abort();
    }
    return out;
}

/**
 * A scalar as the 32 bytes the API takes: leading zero bytes dropped, then left-padded with
 * zeros; a value longer than 32 bytes once stripped ends the test, by name.
 */
inline std::array<std::uint8_t, 32> scalar32(std::span<std::uint8_t const> bytes) {
    auto const first = std::ranges::find_if(bytes, [](std::uint8_t b) { return b != 0; });
    auto const size = static_cast<std::size_t>(bytes.end() - first);
    if (size > 32) {
        std::cerr << "scalar32: scalar of " << size << " bytes after stripping\n";
        std::abort();
    }
    std::array<std::uint8_t, 32> out{};
    std::copy(first, bytes.end(), out.begin() + static_cast<std::ptrdiff_t>(32 - size));
    return out;
}

/**
 * The high-S twin of a compact ECDSA signature: r, then n - s in unsigned arithmetic, with n the
 * group order.
 */
inline std::array<std::uint8_t, 64> negate_s(std::span<std::uint8_t const, 64> compact) {
    auto const order = from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    std::array<std::uint8_t, 64> out{};
    std::ranges::copy(compact, out.begin());
    // Each byte's difference: bit 8 is set when it borrowed.
    unsigned borrow = 0;
    for (std::size_t i = 32; i-- > 0;) {
        unsigned const d = unsigned{order[i]} - unsigned{compact[32 + i]} - borrow;
        out[32 + i] = static_cast<std::uint8_t>(d & 0xffU);
        borrow = (d >> 8U) & 1U;
    }
    return out;
}

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_DATA_HPP
