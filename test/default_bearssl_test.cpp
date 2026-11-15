// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// With BearSSL alone, BearSSL is the default, on every target.

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256_gcm::backend_type::name, "bearssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes128_gcm::backend_type::name, "bearssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256<>::backend_type::name, "bearssl");
    return webcpp::test::exit_status(boost::report_errors());
}
