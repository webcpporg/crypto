// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The install in a program that has not used OpenSSL succeeds (spec section 8.5): the check
// that refuses a late install recognises OpenSSL's own functions. Nothing allocates, so the
// exit check does not apply.

#include "support.hpp"

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    namespace crypto = webcpp::crypto;
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST(crypto::detail::openssl_defaults_installed());
    BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value());
    BOOST_TEST(crypto::detail::openssl_adapter_installed());
    return webcpp::test::exit_status(boost::report_errors());
}
