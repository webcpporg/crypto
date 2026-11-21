// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Natively, with OpenSSL and BearSSL linked, OpenSSL is AES-GCM's default (design D32), on MSVC
// too, and the block cipher's (design D3).

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/ciphers/aes_block.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

int main() {
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256_gcm::backend_type::name, "openssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes128_gcm::backend_type::name, "openssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256<>::backend_type::name, "openssl");
    return webcpp::test::exit_status(boost::report_errors());
}
