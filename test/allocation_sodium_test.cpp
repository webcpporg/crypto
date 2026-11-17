// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On libsodium nothing allocates: make, seal and open of the three ChaCha20-Poly1305 AEADs,
// a failed open included, make no call of operator new, nor of the C library's allocator
// where the target lets a program count it; a control proves the counter moves. Each later
// family on libsodium adds its calls here.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;

/** Makes an AEAD, seals, opens, and opens a forged message: none of it allocates. */
template <class Aead>
void expect_no_allocation() {
    std::array<std::uint8_t, Aead::key_size> key{};
    key.fill(3);
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 13> const additional_data{};
    std::array<std::uint8_t, 4096> data{};
    std::size_t const before = webcpp::test::allocations();
    {
        auto made = Aead::make(key);
        BOOST_TEST(made.has_value());
        auto const tag = made->seal(iv, additional_data, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(made->open(iv, additional_data, data, *tag).has_value());
        std::array<std::uint8_t, Aead::tag_size> const forged{};
        BOOST_TEST(made->open(iv, additional_data, data, forged).error() ==
                   crypto::error::authentication_failed);
        Aead const moved = std::move(*made);
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
}

}  // namespace

int main() {
    // The control: a malloc of the C library's moves the counter where it is counted.
    std::size_t const control = webcpp::test::allocations();
    void* volatile block = std::malloc(40);
    std::free(block);
    // A constant condition: `if constexpr`, which MSVC's C4127 (an error under /W4 /WX) leaves be.
    if constexpr (webcpp::test::c_allocations_counted) {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 1U);
    } else {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 0U);
        std::printf("the C library's allocations are not counted on this target\n");
    }
    // libsodium's initialisation, the first make's, is counted too.
    expect_no_allocation<crypto::ciphers::chacha20_poly1305<crypto::backends::sodium>>();
    expect_no_allocation<crypto::ciphers::chacha20_poly1305_original<crypto::backends::sodium>>();
    expect_no_allocation<crypto::ciphers::xchacha20_poly1305<crypto::backends::sodium>>();
    return webcpp::test::exit_status(boost::report_errors());
}
