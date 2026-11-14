// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The values of webcpp::crypto::error are fixed (spec section 2.9), its category is
// webcpp.crypto, and the two messages the spec writes out are exact.

#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <string_view>

namespace crypto = webcpp::crypto;

int main() {
    using crypto::error;
    BOOST_TEST_EQ(static_cast<int>(error::invalid_key_size), 1);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_iv_size), 2);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_tag_size), 3);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_input_size), 4);
    BOOST_TEST_EQ(static_cast<int>(error::message_too_long), 5);
    BOOST_TEST_EQ(static_cast<int>(error::authentication_failed), 6);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_state), 7);
    BOOST_TEST_EQ(static_cast<int>(error::entropy_unavailable), 8);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_secret_key), 9);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_public_key), 10);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_signature), 11);
    BOOST_TEST_EQ(static_cast<int>(error::backend_failure), 12);

    boost::system::error_code const code = error::authentication_failed;
    BOOST_TEST_EQ(std::string_view(code.category().name()), "webcpp.crypto");
    BOOST_TEST(code.category() == crypto::error_category());

    boost::system::result<void> const failed = error::invalid_state;
    BOOST_TEST(!failed);
    BOOST_TEST(failed.error() == error::invalid_state);

    BOOST_TEST_EQ(crypto::make_error_code(error::authentication_failed).message(),
                  "the authentication tag does not match");
    // 13 and 14 are reserved, not declared: their messages are the unknown one.
    BOOST_TEST_EQ(crypto::make_error_code(static_cast<error>(13)).message(),
                  "unknown webcpp.crypto error");
    BOOST_TEST_EQ(crypto::make_error_code(static_cast<error>(99)).message(),
                  "unknown webcpp.crypto error");
    // The form that allocates nothing returns the whole message, and copies into the buffer
    // what fits, with its terminating zero.
    std::array<char, 8> buffer{};
    BOOST_TEST_EQ(
        std::string_view(crypto::error_category().message(6, buffer.data(), buffer.size())),
        "the authentication tag does not match");
    BOOST_TEST_EQ(std::string_view(buffer.data()), "the aut");
    return webcpp::test::exit_status(boost::report_errors());
}
