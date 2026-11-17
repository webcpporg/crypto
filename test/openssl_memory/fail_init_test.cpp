// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure inside OpenSSL's first initialisation is permanent (spec sections 3.7 and 8.5,
// crypto-r3-review mode failinit): the first allocation after the install fails, make gives
// backend_failure and leaves the queue empty, and a make after the resource has stopped
// failing gives backend_failure again. No entry is raised before the first make, since
// raising one would run OpenSSL's initialisation first.
//
// On OpenSSL 3.5.9 the failing allocation is the base initialisation's first lock
// (crypto/init.c:66, reached from make's ERR_set_mark), so the base is never initialised:
// OpenSSL never registers its cleanup with atexit, and OPENSSL_cleanup would return at once
// (init.c:384). The default library context it built meanwhile is never given back, so the
// exit check cannot hold here and main returns the tests' status.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value());
    auto& resource = webcpp::test::the_counting_resource();
    std::array<std::uint8_t, 32> const key{};

    BOOST_TEST_EQ(resource.allocations(), 0U);
    resource.arm(0);
    auto const first = aead::make(key);
    BOOST_TEST(first.has_error() && first.error() == crypto::error::backend_failure);
    unsigned long code = 0;
    BOOST_TEST_EQ(webcpp::test::drain(code), 0U);

    // The queue may be unusable after the failed initialisation: on OpenSSL 3.5.9 the entry
    // is not raised (measured on macOS and Linux, 2026-11-17), and the queue stays empty.
    unsigned long const ours = webcpp::test::raise_entry();
    auto const second = aead::make(key);
    BOOST_TEST(second.has_error() && second.error() == crypto::error::backend_failure);
    BOOST_TEST_EQ(webcpp::test::drain(code), ours == 0 ? 0U : 1U);
    BOOST_TEST_EQ(code, ours);

    BOOST_TEST(!resource.foreign_free());
    return webcpp::test::exit_status(boost::report_errors());
}
