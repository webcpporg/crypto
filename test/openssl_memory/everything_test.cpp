// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Everything in the resource, refused otherwise (spec section 8.5): installed first, the
// configuration file not read, make, the one-shot and incremental seals, good and failed
// opens and the destructors, for gcm and aes256 on OpenSSL, make no call of the C
// library's allocator from any caller; seal, open and the incremental seal allocate
// nothing anywhere; a second thread does the same (Review Focus 5); no foreign block is
// freed; and after main OpenSSL's cleanup gives every block back (support.hpp's exit).
// Built <threading>multi, so that the provider has threads.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <thread>

namespace {

namespace crypto = webcpp::crypto;
using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;

void messages(aead& made) {
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    auto const& resource = webcpp::test::the_counting_resource();
    std::size_t const before = resource.allocations();
    auto const tag = made.seal(iv, {}, data);
    BOOST_TEST(tag.has_value());
    BOOST_TEST(made.open(iv, {}, data, *tag).has_value());
    std::array<std::uint8_t, 16> const bad{};
    BOOST_TEST(made.open(iv, {}, data, bad).error() == crypto::error::authentication_failed);
    BOOST_TEST(made.begin_seal(iv, {}).has_value());
    BOOST_TEST(made.update(data).has_value());
    BOOST_TEST(made.result().has_value());
    BOOST_TEST_EQ(resource.allocations(), before);
}

}  // namespace

int main() {
    webcpp::test::say_whether_c_is_counted();
    if (!BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    // The configuration file makes the C library allocate its FILE and buffer, which no
    // hook of OpenSSL's reaches (spec section 3.7).
    BOOST_TEST_EQ(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr), 1);
    webcpp_test_count_c_allocations(1);
    {
        std::array<std::uint8_t, 32> const key{};
        auto made = aead::make(key);
        BOOST_TEST(made.has_value());
        messages(*made);
        auto block = crypto::ciphers::aes256<crypto::backends::openssl>::make(key);
        BOOST_TEST(block.has_value());
        std::array<std::uint8_t, 32> blocks{};
        auto const& resource = webcpp::test::the_counting_resource();
        std::size_t const before = resource.allocations();
        BOOST_TEST(block->encrypt(blocks).has_value());
        BOOST_TEST(block->decrypt(blocks).has_value());
        BOOST_TEST_EQ(resource.allocations(), before);
        // Starting and joining a thread allocates in the C library, which is not OpenSSL's:
        // the counter is off around both, and the thread turns it on for its own work.
        webcpp_test_count_c_allocations(0);
        std::thread other([&key] {
            webcpp_test_count_c_allocations(1);
            {
                auto made_there = aead::make(key);
                BOOST_TEST(made_there.has_value());
                messages(*made_there);
            }
            webcpp_test_count_c_allocations(0);
        });
        other.join();
        webcpp_test_count_c_allocations(1);
    }
    webcpp_test_count_c_allocations(0);
    BOOST_TEST_EQ(webcpp_test_c_allocations(), 0U);
    BOOST_TEST(!webcpp::test::the_counting_resource().foreign_free());
    int const errors = boost::report_errors();
    if (errors != 0) {
        return errors;
    }
    webcpp::test::the_counting_resource().main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
