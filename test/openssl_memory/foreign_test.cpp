// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A foreign install is an error value (spec section 8.5, PROBE-R3 mode foreign): another
// party's functions installed with CRYPTO_set_mem_functions, and one allocation made through
// them, make install_memory_functions() give memory_functions_refused and leave that party's
// functions in place. The resource never receives a block, so the exit check does not apply.

#include "support.hpp"

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>

int main() {
    namespace crypto = webcpp::crypto;
    using webcpp::test::other_party;
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST_EQ(other_party::install(), 1);
    OPENSSL_free(OPENSSL_malloc(1));
    BOOST_TEST_EQ(other_party::calls(), 2U);
    auto const installed = crypto::backends::openssl::install_memory_functions();
    BOOST_TEST(installed.has_error() &&
               installed.error() == crypto::error::memory_functions_refused);
    BOOST_TEST(other_party::installed());
    BOOST_TEST_EQ(webcpp::test::the_counting_resource().allocations(), 0U);
    return webcpp::test::exit_status(boost::report_errors());
}
