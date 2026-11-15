// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The block cipher's generic layer on the mock backend (support/mock_backend.hpp): every
// check of support/aes_checks.hpp, the backend's errors passed through as they are, and
// the engine's contract kept throughout.

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"
#include "support/mock_backend.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cstdint>

namespace crypto = webcpp::crypto;
using webcpp::test::mock;
using webcpp::test::mock_control;

namespace {

// make returns the engine's error as it is: not_enough_memory, backend_failure.
void check_make_failures() {
    std::array<std::uint8_t, 16> const key{};
    mock_control.init =
        boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
    BOOST_TEST(crypto::ciphers::aes128<mock>::make(key).error() ==
               boost::system::errc::not_enough_memory);
    mock_control.init = crypto::error::backend_failure;
    BOOST_TEST(crypto::ciphers::aes128<mock>::make(key).error() == crypto::error::backend_failure);
    // The size is checked before the engine is asked.
    BOOST_TEST(crypto::ciphers::aes128<mock>::make(std::span(key).first(8)).error() ==
               crypto::error::invalid_key_size);
    webcpp::test::mock_clear();
    BOOST_TEST(crypto::ciphers::aes128<mock>::make(key).has_value());
}

// encrypt and decrypt return the engine's error as it is, after their own guards.
void check_block_failures() {
    std::array<std::uint8_t, 24> const key{};
    auto made = crypto::ciphers::aes192<mock>::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 32> blocks{};
    mock_control.block = crypto::error::backend_failure;
    BOOST_TEST(made->encrypt(blocks).error() == crypto::error::backend_failure);
    BOOST_TEST(made->decrypt(blocks).error() == crypto::error::backend_failure);
    BOOST_TEST(made->encrypt(std::span(blocks).first(5)).error() ==
               crypto::error::invalid_input_size);
    webcpp::test::mock_clear();
    BOOST_TEST(made->encrypt(blocks).has_value());
}

}  // namespace

int main() {
    webcpp::test::check_block_cipher<mock>();
    check_make_failures();
    check_block_failures();
    BOOST_TEST_EQ(mock_control.violations, 0);
    return webcpp::test::exit_status(boost::report_errors());
}
