// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// random_device fills buffers of 0, 1, 256, 257, 65,536 and 65,537 bytes from the
// system's generator, two fills differ, and with exceptions it is a
// UniformRandomBitGenerator (spec sections 2.7 and 8.4).

#include <webcpp/crypto/random_device.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <random>
#include <vector>

namespace crypto = webcpp::crypto;

namespace {

void fills(std::size_t size) {
    crypto::random_device device;
    std::vector<std::uint8_t> first(size);
    std::vector<std::uint8_t> second(size);
    BOOST_TEST(device.fill(first));
    BOOST_TEST(device.fill(second));
    if (size >= 16) {
        BOOST_TEST(first != second);
        BOOST_TEST(std::ranges::any_of(first, [](std::uint8_t b) { return b != 0; }));
    }
}

}  // namespace

int main() {
    for (std::size_t const size : {0, 1, 256, 257, 65'536, 65'537}) {
        fills(size);
    }
    BOOST_TEST_EQ((crypto::random_device::min)(), 0U);
    BOOST_TEST_EQ((crypto::random_device::max)(), (std::numeric_limits<unsigned int>::max)());
    BOOST_TEST_EQ(crypto::random_device().entropy(),
                  static_cast<double>(std::numeric_limits<unsigned int>::digits));
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    static_assert(std::uniform_random_bit_generator<crypto::random_device>);
    crypto::random_device device;
    std::uniform_int_distribution<int> die(1, 6);
    int const roll = die(device);
    BOOST_TEST(roll >= 1 && roll <= 6);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
