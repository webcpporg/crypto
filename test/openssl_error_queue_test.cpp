// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL's error queue (spec section 3.3): on an empty queue, a make of the block cipher
// and of gcm leaves it empty; an entry of the caller's survives a make, a seal, a good open
// and a failed one, and nothing of webcpp's is left beside it.

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/err.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace {

/** The queue's entries, oldest first, emptied. */
std::size_t drain(unsigned long& first) {
    std::size_t count = 0;
    first = ERR_peek_error();
    while (ERR_get_error() != 0) {
        ++count;
    }
    return count;
}

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    using aead = crypto::gcm<crypto::aes256<crypto::backends::openssl>>;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 32> data{};

    // OpenSSL's first fetch and its initialisation leave nothing behind either.
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    BOOST_TEST(crypto::aes256<crypto::backends::openssl>::make(key).has_value());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    BOOST_TEST(aead::make(key).has_value());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);

    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    auto made = aead::make(key);
    BOOST_TEST(made.has_value());
    auto const tag = made->seal(iv, {}, data);
    BOOST_TEST(tag.has_value());
    BOOST_TEST(made->open(iv, {}, data, *tag).has_value());
    std::array<std::uint8_t, 16> bad{};
    BOOST_TEST(made->open(iv, {}, data, bad).error() == crypto::error::authentication_failed);
    unsigned long first = 0;
    BOOST_TEST_EQ(drain(first), 1U);
    BOOST_TEST_EQ(first, ours);
    return webcpp::test::exit_status(boost::report_errors());
}
