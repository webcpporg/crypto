// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On wasip2 and wasip3, with both linked and WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL defined,
// OpenSSL is the default.

#include <webcpp/crypto/aes256_gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    BOOST_TEST_EQ(webcpp::crypto::aes256_gcm::backend_type::name, "openssl");
    BOOST_TEST_EQ(webcpp::crypto::aes128_gcm::backend_type::name, "openssl");
    BOOST_TEST_EQ(webcpp::crypto::aes256<>::backend_type::name, "openssl");
    return webcpp::test::exit_status(boost::report_errors());
}
