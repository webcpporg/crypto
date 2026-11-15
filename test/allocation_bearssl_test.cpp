// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On BearSSL nothing allocates (spec section 3.2): make, seal, open, the incremental seal,
// equal and random_device's fill make no call of operator new, nor of the C library's
// allocator where the target lets a program count it; a control proves the counter moves.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: a test
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"
#include "support/gcm_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

int main() {
    namespace crypto = webcpp::crypto;
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
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 4096> data{};
    std::size_t const before = webcpp::test::allocations();
    {
        crypto::random_device device;  // lint-world: a test
        BOOST_TEST(device.fill(key).has_value());
        auto made =
            crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
        BOOST_TEST(made.has_value());
        auto const tag = made->seal(iv, {}, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(made->open(iv, {}, data, *tag).has_value());
        BOOST_TEST(made->begin_seal(iv, {}).has_value());
        BOOST_TEST(made->update(data).has_value());
        BOOST_TEST(made->result().has_value());
        BOOST_TEST(crypto::equal(*tag, *tag));
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
    return webcpp::test::exit_status(boost::report_errors());
}
