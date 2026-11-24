// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The values of webcpp::crypto::error are fixed (spec section 2.9), its category is
// webcpp.crypto, every defined value has a message of its own, a value that is not defined
// has the unknown message, and the buffer form of message() copies and truncates exactly.

#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <set>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;

int main() {
    using crypto::error;
    BOOST_TEST_EQ(static_cast<int>(error::invalid_key_size), 1);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_nonce_size), 2);
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
    BOOST_TEST_EQ(static_cast<int>(error::memory_functions_refused), 13);
    BOOST_TEST_EQ(static_cast<int>(error::memory_functions_not_installed), 14);
    BOOST_TEST_EQ(static_cast<int>(error::weak_public_key), 15);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_point), 16);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_scalar), 17);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_padding), 18);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_encoding), 19);
    BOOST_TEST_EQ(static_cast<int>(error::invalid_ciphertext_size), 20);

    boost::system::error_code const code = error::authentication_failed;
    BOOST_TEST_EQ(std::string_view(code.category().name()), "webcpp.crypto");
    BOOST_TEST(code.category() == crypto::error_category());

    boost::system::result<void> const failed = error::invalid_state;
    BOOST_TEST(!failed);
    BOOST_TEST(failed.error() == error::invalid_state);

    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_nonce_size).message(),
                  "the nonce is not of a size the algorithm accepts");
    BOOST_TEST_EQ(crypto::make_error_code(error::authentication_failed).message(),
                  "the authentication tag does not match");
    // The memory option's two errors carry spec section 3.7's texts.
    BOOST_TEST_EQ(
        crypto::make_error_code(error::memory_functions_refused).message(),
        "OpenSSL's memory functions cannot be installed: OpenSSL has already allocated, or "
        "another party installed its own. Call backends::openssl::install_memory_functions() as "
        "the first statement of main, before anything uses OpenSSL.");
    BOOST_TEST_EQ(
        crypto::make_error_code(error::memory_functions_not_installed).message(),
        "OpenSSL's memory functions are not webcpp::crypto's. Call "
        "backends::openssl::install_memory_functions() as the first statement of main, and let "
        "nothing else call CRYPTO_set_mem_functions.");
    BOOST_TEST_EQ(crypto::make_error_code(static_cast<error>(99)).message(),
                  "unknown webcpp.crypto error");
    // The form that allocates nothing returns the whole message, and copies into the buffer
    // what fits, with its terminating zero.
    std::array<char, 8> buffer{};
    BOOST_TEST_EQ(
        std::string_view(crypto::error_category().message(6, buffer.data(), buffer.size())),
        "the authentication tag does not match");
    BOOST_TEST_EQ(std::string_view(buffer.data()), "the aut");

    BOOST_TEST_EQ(crypto::make_error_code(error::weak_public_key).message(),
                  "the public key is weak: of small order, or the shared secret is zero");
    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_point).message(),
                  "the encoding is not a canonical element of the group");
    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_scalar).message(),
                  "the scalar is not reduced, or is zero");
    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_padding).message(),
                  "the padding is not valid");
    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_encoding).message(),
                  "the encoding does not decode");
    BOOST_TEST_EQ(crypto::make_error_code(error::invalid_ciphertext_size).message(),
                  "the ciphertext is not of the key's size");

    // Every defined value has its own message, never the unknown one.
    std::set<std::string> messages;
    for (int value = 1; value <= 20; ++value) {
        std::string const text = crypto::error_category().message(value);
        BOOST_TEST(!text.empty());
        BOOST_TEST_NE(text, "unknown webcpp.crypto error");
        messages.insert(text);
    }
    BOOST_TEST_EQ(messages.size(), 20u);

    // The guards of the buffer form: a null buffer or a size of 0 writes nothing, a size of 1
    // writes the terminating zero alone, and a message longer than the buffer is cut with one.
    BOOST_TEST_EQ(std::string_view(crypto::error_category().message(6, nullptr, 8)),
                  "the authentication tag does not match");
    std::array<char, 4> guard{'x', 'x', 'x', 'x'};
    BOOST_TEST_EQ(std::string_view(crypto::error_category().message(6, guard.data(), 0)),
                  "the authentication tag does not match");
    BOOST_TEST(guard == (std::array<char, 4>{'x', 'x', 'x', 'x'}));
    BOOST_TEST_EQ(std::string_view(crypto::error_category().message(6, guard.data(), 1)),
                  "the authentication tag does not match");
    BOOST_TEST(guard == (std::array<char, 4>{'\0', 'x', 'x', 'x'}));
    guard = {'x', 'x', 'x', 'x'};
    crypto::error_category().message(6, guard.data(), guard.size());
    BOOST_TEST(guard == (std::array<char, 4>{'t', 'h', 'e', '\0'}));
    return webcpp::test::exit_status(boost::report_errors());
}
