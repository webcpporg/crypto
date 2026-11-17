// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of a key pair that holds no key (moved from, or refused by a tweak) that the
// secp256k1 tests share.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_CHECKS_HPP

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>

namespace webcpp::test {

/**
 * Every operation of a key pair that holds no key answers `invalid_state`: the pair is empty,
 * as the source of a move is and as a pair is that a tweak refused.
 *
 * @param key The pair, which the tweak is asked of (it stays empty).
 */
inline void expect_empty_keypair(webcpp::crypto::curves::secp256k1::keypair& key) {
    auto const live = webcpp::crypto::curves::secp256k1::keypair::make(std::array<std::uint8_t, 32>{
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    });
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    std::array<std::uint8_t, 32> const tweak{};
    BOOST_TEST(key.xonly_public_key().error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.public_key().error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign_schnorr(message, aux).error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.public_key_uncompressed().error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign_ecdsa(message).error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign_ecdsa(message, aux).error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign_recoverable(message).error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.tweak_xonly(tweak).error() == webcpp::crypto::error::invalid_state);
    std::array<std::uint8_t, webcpp::crypto::curves::secp256k1::max_pkcs8_size> encoding{};
    BOOST_TEST(webcpp::crypto::curves::secp256k1::encode_pkcs8(key, encoding).error() ==
               webcpp::crypto::error::invalid_state);
    if (BOOST_TEST(live.has_value())) {
        auto const peer = *live->public_key();
        BOOST_TEST(key.ecdh(peer).error() == webcpp::crypto::error::invalid_state);
        BOOST_TEST(key.ecdh_x(peer).error() == webcpp::crypto::error::invalid_state);
        BOOST_TEST(key.ecdh_point(peer).error() == webcpp::crypto::error::invalid_state);
    }
}

}  // namespace webcpp::test

#endif
