// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL's error queue (spec section 3.3): on an empty queue, a from_key of the block cipher,
// of gcm and of ChaCha20-Poly1305 leaves it empty; for each AEAD, an entry of the caller's
// survives a from_key, a seal, a good open and a failed one, and nothing of webcpp's is left
// beside it.

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <openssl/err.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

namespace crypto = webcpp::crypto;

/** The queue's entries, oldest first, emptied. */
std::size_t drain(unsigned long& first) {
    std::size_t count = 0;
    first = ERR_peek_error();
    while (ERR_get_error() != 0) {
        ++count;
    }
    return count;
}

/**
 * An entry of the caller's survives a from_key of `Aead`, a seal, a good open and a failed one, and
 * is the queue's one entry afterwards.
 */
template <class Aead>
void check_queue(std::span<std::uint8_t const> key, std::span<std::uint8_t const> nonce) {
    std::array<std::uint8_t, 32> data{};
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's reason macro ORs signed flags
    ERR_raise(ERR_LIB_USER, ERR_R_PASSED_INVALID_ARGUMENT);
    unsigned long const ours = ERR_peek_last_error();
    auto made = Aead::from_key(key);
    BOOST_TEST(made.has_value());
    if (!made) {
        return;
    }
    auto const tag = made->seal(nonce, {}, data);
    BOOST_TEST(tag.has_value());
    BOOST_TEST(tag && made->open(nonce, {}, data, *tag).has_value());
    std::array<std::uint8_t, Aead::tag_size> const bad{};
    BOOST_TEST(made->open(nonce, {}, data, bad).error() == crypto::error::authentication_failed);
    unsigned long first = 0;
    BOOST_TEST_EQ(drain(first), 1U);
    BOOST_TEST_EQ(first, ours);
}

}  // namespace

int main() {
    using gcm = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>;
    using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::openssl>;
    std::array<std::uint8_t, 32> const key{};
    std::array<std::uint8_t, 12> const nonce{};

    // OpenSSL's first fetch and its initialisation leave nothing behind either.
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    BOOST_TEST(crypto::ciphers::aes256<crypto::backends::openssl>::from_key(key).has_value());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    BOOST_TEST(gcm::from_key(key).has_value());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    BOOST_TEST(chacha::from_key(key).has_value());
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);

    check_queue<gcm>(key, nonce);
    check_queue<chacha>(key, nonce);
    return webcpp::test::exit_status(boost::report_errors());
}
