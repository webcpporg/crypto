// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On wasip2 and wasip3, with OpenSSL and BearSSL linked, BearSSL is the default: OpenSSL is
// never the default on WebAssembly (design D32).

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256_gcm::backend_type::name, "bearssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes128_gcm::backend_type::name, "bearssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256<>::backend_type::name, "bearssl");
    return webcpp::test::exit_status(boost::report_errors());
}
