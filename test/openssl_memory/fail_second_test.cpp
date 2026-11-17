// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A failing resource after a good make (spec sections 3.7 and 8.5, crypto-r3-review mode
// failsecond): the next make's allocation in EVP_CIPHER_CTX_new fails and gives
// errc::not_enough_memory, a make after it succeeds, and a failing allocation in
// EVP_EncryptInit_ex gives backend_failure. Before each make the test raises an entry of its
// own, and after it the thread's queue holds that entry alone. The program ends through the
// exit check.

#include "support.hpp"

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace {

namespace crypto = webcpp::crypto;
using aead = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;

// A make after the first takes two blocks on OpenSSL 3.5.9 (measured on macOS and Linux,
// 2026-11-17): EVP_CIPHER_fetch finds the cipher in its cache and allocates nothing, then
// EVP_CIPHER_CTX_new takes the first block and EVP_EncryptInit_ex the second.
constexpr std::size_t context_new = 0;
constexpr std::size_t encrypt_init = 1;

// Raises the test's entry, makes with the resource armed to fail after `failing_after`
// allocations (or not armed), and checks that the queue holds the test's entry alone
// afterwards.
boost::system::result<aead> make_between_entries(std::array<std::uint8_t, 32> const& key,
                                                 std::optional<std::size_t> failing_after) {
    unsigned long const ours = webcpp::test::raise_entry();
    BOOST_TEST_NE(ours, 0UL);
    if (failing_after) {
        webcpp::test::the_counting_resource().arm(*failing_after);
    }
    auto made = aead::make(key);
    unsigned long first = 0;
    BOOST_TEST_EQ(webcpp::test::drain(first), 1U);
    BOOST_TEST_EQ(first, ours);
    return made;
}

}  // namespace

int main() {
    webcpp::test::say_whether_c_is_counted();
    BOOST_TEST(crypto::backends::openssl::install_memory_functions().has_value());
    std::array<std::uint8_t, 32> const key{};
    BOOST_TEST(aead::make(key).has_value());

    auto const no_context = make_between_entries(key, context_new);
    BOOST_TEST(no_context.has_error() &&
               no_context.error() == boost::system::errc::not_enough_memory);
    BOOST_TEST(make_between_entries(key, std::nullopt).has_value());
    auto const no_init = make_between_entries(key, encrypt_init);
    BOOST_TEST(no_init.has_error() && no_init.error() == crypto::error::backend_failure);
    BOOST_TEST(make_between_entries(key, std::nullopt).has_value());

    auto& resource = webcpp::test::the_counting_resource();
    BOOST_TEST(!resource.foreign_free());
    if (int const errors = boost::report_errors(); errors != 0) {
        return webcpp::test::exit_status(errors);
    }
    resource.main_returned();
    return 3;  // the resource ends the process with 0 once OpenSSL has freed everything
}
