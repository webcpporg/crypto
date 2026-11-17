// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure inside OpenSSL's first initialisation is permanent (spec sections 3.7 and 8.5,
// crypto-r3-review mode failinit): the first allocation after the install fails, make gives
// backend_failure, and a make after the resource has stopped failing gives backend_failure
// again. No entry is raised before the first make, since raising one would run OpenSSL's
// initialisation first.
//
// What follows is OpenSSL 3.5.9's, measured on macOS and Linux (2026-11-17), and pinned so
// that a pin move that changes it fails here. The failing allocation is the base
// initialisation's first lock (crypto/init.c:66, reached from make's ERR_set_mark), so the
// base is never initialised:
// - the error queue's state cannot be made, so no entry can be raised afterwards and the
//   queue stays empty whatever make does;
// - OpenSSL never registers its cleanup with atexit, and OPENSSL_cleanup returns at once
//   (init.c:384), so the blocks the default library context took meanwhile stay live in
//   the resource until the process ends. The exit check cannot hold here: main returns the
//   tests' status, and prints the count of those blocks.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value());
    auto& resource = webcpp::test::the_counting_resource();
    std::array<std::uint8_t, 32> const key{};
    BOOST_TEST_EQ(resource.allocations(), 0U);
    {
        resource.arm(0);
        auto const first = aead::make(key);
        BOOST_TEST(first.has_error() && first.error() == crypto::error::backend_failure);
        BOOST_TEST_EQ(webcpp::test::raise_entry(), 0UL);
        auto const second = aead::make(key);
        BOOST_TEST(second.has_error() && second.error() == crypto::error::backend_failure);
    }

    std::size_t const live = resource.live();
    BOOST_TEST_NE(live, 0U);
    OPENSSL_cleanup();
    BOOST_TEST_EQ(resource.live(), live);
    webcpp::test::write_out("blocks left live by the failed initialisation, never given back: " +
                            std::to_string(live) + "\n");

    BOOST_TEST(!resource.foreign_free());
    return webcpp::test::exit_status(boost::report_errors());
}
