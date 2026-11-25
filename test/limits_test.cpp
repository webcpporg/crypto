// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::exceeds compares in 64 bits on every target.

#include <webcpp/crypto/detail/limits.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <cstdint>

namespace detail = webcpp::crypto::detail;

int main() {
    BOOST_TEST(detail::exceeds((std::uint64_t{1} << 36U) - 31, (std::uint64_t{1} << 36U) - 32));
    BOOST_TEST(!detail::exceeds((std::uint64_t{1} << 36U) - 32, (std::uint64_t{1} << 36U) - 32));
    return webcpp::test::exit_status(boost::report_errors());
}
