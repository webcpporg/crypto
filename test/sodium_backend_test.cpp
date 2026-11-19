// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#include <webcpp/crypto/backends/sodium.hpp>

#include <boost/core/lightweight_test.hpp>
#include <webcpp/test/exit_status.hpp>

namespace crypto = webcpp::crypto;

int main() {
    BOOST_TEST_EQ(crypto::backends::sodium::name, "sodium");
    BOOST_TEST(crypto::detail::sodium_ready().has_value());
    // A second call is libsodium's no-op (sodium_init returns 1), still a success.
    BOOST_TEST(crypto::detail::sodium_ready().has_value());
    return webcpp::test::exit_status(boost::report_errors());
}
