// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failure inside OpenSSL's first initialisation (spec sections 3.7 and 8.5,
// crypto-r3-review mode failinit), on an OpenSSL built without threads: the first allocation
// after the install fails, from_key gives backend_failure, and a from_key after the resource has
// stopped failing gives backend_failure again. No entry is raised before the first from_key, since
// raising one would run OpenSSL's initialisation first.
//
// What follows is OpenSSL 3.5.9's, measured on macOS and Linux (2026-11-17), and pinned so
// that a pin move that changes it fails here. The failing allocation is the base
// initialisation's first lock (crypto/init.c:66, reached from from_key's ERR_set_mark), so the
// base is never initialised:
// - the error queue's state cannot be made, so no entry can be raised afterwards and the
//   queue stays empty whatever from_key does;
// - OpenSSL never registers its cleanup with atexit, and OPENSSL_cleanup returns at once
//   (init.c:384), so the blocks the default library context took meanwhile stay live in
//   the resource until the process ends. The exit check cannot hold here: main returns the
//   tests' status, and prints the count of those blocks.
//
// On an OpenSSL built with threads (OPENSSL_THREADS: MSVC's only build, and b2's
// threading=multi elsewhere, which the Jamfile's fail_init_threads asks for) the failure is
// not recoverable and is not run. There the lock is allocated with a file and a line
// (crypto/threads_pthread.c, threads_win.c), so CRYPTO_malloc's failure path raises an error,
// whose state needs the base initialisation that is running: OpenSSL re-enters its own
// run-once, which aborts on macOS, deadlocks on Linux and spins on Windows. Without threads
// the lock is allocated with neither (threads_none.c), nothing is raised, and the failure
// returns. The threaded program pins the documented boundary instead: the first from_key, with a
// resource that does not fail, runs OpenSSL's initialisation through the resource, which must
// therefore serve it; the count is printed. It ends through the exit check.

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
#ifdef OPENSSL_THREADS
    {
        auto const first = aead::from_key(key);
        BOOST_TEST(first.has_value());
    }
    std::size_t const taken = resource.allocations();
    BOOST_TEST_NE(taken, 0U);
    webcpp::test::write_out(
        "OpenSSL is built with threads: the resource is not made to fail; the first from_key "
        "took " +
        std::to_string(taken) + " blocks of it, OpenSSL's initialisation among them\n");
    BOOST_TEST(!resource.foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    resource.main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
#else
    // The makes live in this scope so that their objects are destroyed before the explicit
    // OPENSSL_cleanup() below: should a pin move let OpenSSL initialise, no context is then
    // freed after the cleanup, and the live count compared across it is the library's alone.
    {
        resource.arm(0);
        auto const first = aead::from_key(key);
        BOOST_TEST(first.has_error() && first.error() == crypto::error::backend_failure);
        BOOST_TEST_EQ(webcpp::test::raise_entry(), 0UL);
        auto const second = aead::from_key(key);
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
#endif
}
