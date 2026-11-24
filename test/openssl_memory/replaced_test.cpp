// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Replaced functions are an error value (spec section 8.5, PROBE-R3 mode on): after an
// install and a from_key, a second party installs its own functions, which OpenSSL accepts; the
// next from_key gives memory_functions_not_installed and calls nothing of OpenSSL's, so that the
// second party's functions are never called. The adapter is put back before main returns,
// so that OpenSSL's cleanup frees through it, and the program ends through the exit check.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    using webcpp::test::other_party;
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value());
    std::array<std::uint8_t, 32> const key{};
    // Destroyed before the replacement: its free goes to the resource that gave its blocks.
    BOOST_TEST(aead::from_key(key).has_value());
    BOOST_TEST_EQ(other_party::install(), 1);
    auto const replaced = aead::from_key(key);
    BOOST_TEST(replaced.has_error() &&
               replaced.error() == crypto::error::memory_functions_not_installed);
    BOOST_TEST_EQ(other_party::calls(), 0U);
    BOOST_TEST_EQ(
        CRYPTO_set_mem_functions(&webcpp_crypto_openssl_malloc, &webcpp_crypto_openssl_realloc,
                                 &webcpp_crypto_openssl_free),
        1);
    BOOST_TEST(aead::from_key(key).has_value());
    auto& resource = webcpp::test::the_counting_resource();
    BOOST_TEST(!resource.foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    resource.main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
