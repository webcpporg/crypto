// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A forgotten install is an error value (spec section 8.5): built with the option and
// without the install, make gives memory_functions_not_installed with section 3.7's
// message, and OpenSSL has allocated nothing, since the guard comes before the error queue's
// mark: its defaults are still replaceable, CRYPTO_set_mem_functions returning 1. The
// program then makes and seals through the adapter, and ends through the exit check.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstdint>
#include <string>

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    webcpp::test::say_whether_c_is_counted();
    auto& resource = webcpp::test::the_counting_resource();
    std::array<std::uint8_t, 32> const key{};
    auto const forgotten = aead::make(key);
    // On success error() is the empty code, which fails both checks below.
    BOOST_TEST(forgotten.error() == crypto::error::memory_functions_not_installed);
    BOOST_TEST_EQ(forgotten.error().message(),
                  std::string("OpenSSL's memory functions are not webcpp::crypto's. Call "
                              "backends::openssl::install_memory_functions() as the first "
                              "statement of main, and let nothing else call "
                              "CRYPTO_set_mem_functions."));
    BOOST_TEST_EQ(
        CRYPTO_set_mem_functions(&webcpp_crypto_openssl_malloc, &webcpp_crypto_openssl_realloc,
                                 &webcpp_crypto_openssl_free),
        1);
    {
        auto made = aead::make(key);
        BOOST_TEST(made.has_value());
        std::array<std::uint8_t, 12> const iv{};
        std::array<std::uint8_t, 64> data{};
        BOOST_TEST(made.has_value() && made->seal(iv, {}, data).has_value());
    }
    BOOST_TEST(!resource.foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    resource.main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
