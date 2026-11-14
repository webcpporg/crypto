// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Readers the secp256k1 vector tests share: a whole file as text, a base64url string
// without padding, and a scalar normalised to the 32 bytes the secp256k1 API takes.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_DATA_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_DATA_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {

/** The whole file at path; one that cannot be opened ends the test, by name. */
inline std::string read_text(std::string const& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "cannot open test data: " << path << '\n';
        std::abort();
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/**
 * The bytes of a base64url string without padding (`-` and `_`); any other character ends
 * the test, by name.
 */
inline std::vector<std::uint8_t> from_base64url(std::string_view text) {
    std::vector<std::uint8_t> out;
    std::uint32_t bits = 0;
    int count = 0;
    for (char c : text) {
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
    return out;
}

/**
 * A scalar as the 32 bytes the API takes: leading zero bytes dropped, then left-padded with
 * zeros; a value longer than 32 bytes once stripped ends the test, by name.
 */
inline std::array<std::uint8_t, 32> scalar32(std::span<std::uint8_t const> bytes) {
    auto const first =
        std::find_if(bytes.begin(), bytes.end(), [](std::uint8_t b) { return b != 0; });
    auto const size = static_cast<std::size_t>(bytes.end() - first);
    if (size > 32) {
        std::cerr << "scalar32: scalar of " << size << " bytes after stripping\n";
        std::abort();
    }
    std::array<std::uint8_t, 32> out{};
    std::copy(first, bytes.end(), out.begin() + static_cast<std::ptrdiff_t>(32 - size));
    return out;
}

}  // namespace webcpp::test

#endif
