// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// asio's and crypto's OpenSSL aliases in one program: both defines, one OpenSSL 3.5.9,
// and one EVP call, so the link holds libcrypto.

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>

int main() {
#if !defined(WEBCPP_CRYPTO_HAS_OPENSSL) || !defined(WEBCPP_ASIO_HAS_OPENSSL)
    BOOST_ERROR("both aliases give their define");
#endif
    BOOST_TEST_EQ(OpenSSL_version_num(), 0x30500090UL);  // tools/openssl/pin.json: 3.5.9
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
    BOOST_TEST(cipher != nullptr);
    if (cipher != nullptr) {
        BOOST_TEST_EQ(EVP_CIPHER_get_key_length(cipher), 32);
        EVP_CIPHER_free(cipher);
    }
    return webcpp::test::exit_status(boost::report_errors());
}
