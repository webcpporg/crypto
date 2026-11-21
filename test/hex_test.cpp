// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The tests' hex readers (support/hex.hpp): hex<N> decodes at compile time, either case, into the
// bytes from_hex decodes at run time; to_hex writes them back in lower case.

#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>

namespace {

namespace test = webcpp::test;

// Decoded by the compiler: a wrong byte fails the build.
static_assert(test::hex<4>("00ff7Fa0") == std::array<std::uint8_t, 4>{0x00, 0xff, 0x7f, 0xa0});
static_assert(test::hex<0>("").empty());

constexpr auto mixed = test::hex<8>("0123456789AbCdEf");

}  // namespace

int main() {
    auto const decoded = test::from_hex("0123456789abcdef");
    BOOST_TEST(std::ranges::equal(mixed, decoded));
    BOOST_TEST_EQ(test::to_hex(mixed), "0123456789abcdef");
    return webcpp::test::exit_status(boost::report_errors());
}
