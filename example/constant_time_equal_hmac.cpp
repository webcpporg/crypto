// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Checks an HMAC-SHA-256 tag from Boost.Hash2 with webcpp::secure::constant_time_equal, the
// constant-time comparison. Comparing tags with == or memcmp stops at the first difference, and
// that timing lets an attacker guess a valid tag one byte at a time.
// tag::program[]
#include <webcpp/secure/constant_time_equal.hpp>

#include <boost/hash2/hmac.hpp>
#include <boost/hash2/sha2.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace secure = webcpp::secure;
namespace hash2 = boost::hash2;

int main() {
    // RFC 4231, test case 2.
    std::string_view const key = "Jefe";
    std::string_view const data = "what do ya want for nothing?";
    std::array<std::uint8_t, 32> const sent_tag{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
        0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
        0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };

    // tag::check[]
    // The receiver recomputes the tag and compares it in constant time.
    hash2::hmac_sha2_256 mac(key.data(), key.size());
    mac.update(data.data(), data.size());
    auto const computed = mac.result();
    bool const valid = secure::constant_time_equal(
        std::span<std::uint8_t const>(computed.data(), computed.size()), sent_tag);
    // end::check[]
    if (!valid) {
        return 1;
    }
    std::printf("hmac verified with constant_time_equal\n");

    // A tag with one changed byte must be refused.
    auto altered = sent_tag;
    altered[31] ^= 1U;
    if (secure::constant_time_equal(std::span<std::uint8_t const>(computed.data(), computed.size()),
                                    altered)) {
        return 1;
    }
    std::printf("altered tag refused\n");
    return 0;
}

// end::program[]
