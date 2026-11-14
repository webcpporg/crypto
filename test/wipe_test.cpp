// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::wipe zeroes every byte it is given and none around it; detail::exceeds compares
// in 64 bits on every target.

#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

namespace detail = webcpp::crypto::detail;

int main() {
    std::array<std::uint8_t, 34> bytes{};
    bytes.fill(0xa5);
    detail::wipe(bytes.data() + 1, 32);
    BOOST_TEST_EQ(bytes.front(), 0xa5);
    BOOST_TEST_EQ(bytes.back(), 0xa5);
    for (std::size_t i = 1; i < 33; ++i) {
        BOOST_TEST_EQ(bytes[i], 0);
    }

    struct schedule {
        std::array<std::uint32_t, 4> words;
    } object{{{1, 2, 3, 4}}};

    detail::wipe_object(object);
    BOOST_TEST_EQ(object.words[0] | object.words[1] | object.words[2] | object.words[3], 0U);
    detail::wipe(nullptr, 0);

    BOOST_TEST(detail::exceeds((std::uint64_t{1} << 36U) - 31, (std::uint64_t{1} << 36U) - 32));
    BOOST_TEST(!detail::exceeds((std::uint64_t{1} << 36U) - 32, (std::uint64_t{1} << 36U) - 32));
    return webcpp::test::exit_status(boost::report_errors());
}
