// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A late install is an error value (spec section 8.5, PROBE-R3 mode late): once OpenSSL has
// allocated through its own functions, install_memory_functions() gives
// memory_functions_refused with section 3.7's message, and OpenSSL's own functions stay in
// place. The resource never receives a block, so the exit check does not apply.

#include "support.hpp"

#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/evp.h>

#include <string>

int main() {
    namespace crypto = webcpp::crypto;
    webcpp::test::say_whether_c_is_counted();
    EVP_CIPHER_free(EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr));
    auto const installed = crypto::backends::openssl::install_memory_functions();
    // On success error() is the empty code, which fails both checks below.
    BOOST_TEST(installed.error() == crypto::error::memory_functions_refused);
    BOOST_TEST_EQ(installed.error().message(),
                  std::string("OpenSSL's memory functions cannot be installed: OpenSSL has "
                              "already allocated, or another party installed its own. Call "
                              "backends::openssl::install_memory_functions() as the first "
                              "statement of main, before anything uses OpenSSL."));
    BOOST_TEST(crypto::detail::openssl_defaults_installed());
    BOOST_TEST_EQ(webcpp::test::the_counting_resource().allocations(), 0U);
    return webcpp::test::exit_status(boost::report_errors());
}
