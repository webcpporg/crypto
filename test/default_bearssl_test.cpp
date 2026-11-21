// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On WebAssembly, with BearSSL alone, BearSSL is AES-GCM's default (design D32); natively
// OpenSSL is, and test/messages/gcm_default_openssl_not_linked stops the same program. The block
// cipher's default there is ctaes, whatever is linked (design D3): aes256<> names it, though this
// program does not link it.

#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <type_traits>

static_assert(std::is_same_v<webcpp::crypto::ciphers::aes256<>::backend_type,
                             webcpp::crypto::backends::ctaes>);

int main() {
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes256_gcm::backend_type::name, "bearssl");
    BOOST_TEST_EQ(webcpp::crypto::ciphers::aes128_gcm::backend_type::name, "bearssl");
    return webcpp::test::exit_status(boost::report_errors());
}
