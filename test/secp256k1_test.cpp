// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's key pair and verifications (spec section 2.8): signatures that verify and a
// changed message that does not, ECDSA in low-S compact form, ECDH agreeing between two
// parties, every error of make, a moved-from key pair, and public keys refused in every way
// they can be wrong.

#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cstdint>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::secp256k1;

namespace {

secp::keypair from_byte(std::uint8_t b) {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(b);
    return *secp::keypair::make(secret);
}

void schnorr() {
    auto const key = from_byte(0x42);
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    std::array<std::uint8_t, 32> const aux{};
    auto const signature = key.sign_schnorr(message, aux);
    auto const public_key = key.xonly_public_key();
    BOOST_TEST(signature && public_key);
    BOOST_TEST(secp::verify_schnorr(*signature, message, *public_key).has_value());
    message[0] ^= 1;
    BOOST_TEST(secp::verify_schnorr(*signature, message, *public_key).error() ==
               crypto::error::invalid_signature);
    // Any length, the empty message included (BIP340).
    auto const empty = key.sign_schnorr(std::span<std::uint8_t const>(), aux);
    BOOST_TEST(empty && secp::verify_schnorr(*empty, {}, *public_key).has_value());
    std::array<std::uint8_t, 32> const not_a_point{};  // x = 0 has no point
    BOOST_TEST(secp::verify_schnorr(*signature, message, not_a_point).error() ==
               crypto::error::invalid_public_key);
}

void ecdsa() {
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x99);
    auto const signature = key.sign_ecdsa(hash);
    auto const public_key = key.public_key();
    BOOST_TEST(signature && public_key);
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, *public_key).has_value());
    // Low-S: s is at most half the group order, so its first byte is below 0x80.
    BOOST_TEST((*signature)[32] < 0x80);
    // The high-S form of the same signature is refused, as libsecp256k1's verify refuses it.
    auto high = *signature;
    // n - s, big-endian, with n the group order.
    auto const order =
        webcpp::test::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    int borrow = 0;
    for (int i = 31; i >= 0; --i) {
        int const d = order[static_cast<std::size_t>(i)] -
                      (*signature)[static_cast<std::size_t>(32 + i)] - borrow;
        high[static_cast<std::size_t>(32 + i)] = static_cast<std::uint8_t>(d & 0xff);
        borrow = d < 0 ? 1 : 0;
    }
    BOOST_TEST(secp::verify_ecdsa(high, hash, *public_key).error() ==
               crypto::error::invalid_signature);
    std::array<std::uint8_t, 64> overflow{};
    overflow.fill(0xff);  // r and s not below the order: the compact parser refuses it
    BOOST_TEST(secp::verify_ecdsa(overflow, hash, *public_key).error() ==
               crypto::error::invalid_signature);
    std::array<std::uint8_t, 34> wrong_size{};
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, wrong_size).error() ==
               crypto::error::invalid_public_key);
    auto bad_prefix = *public_key;
    bad_prefix[0] = 0x05;
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, bad_prefix).error() ==
               crypto::error::invalid_public_key);
}

void ecdh() {
    auto const a = from_byte(0x11);
    auto const b = from_byte(0x22);
    auto const shared_a = a.ecdh(*b.public_key());
    auto const shared_b = b.ecdh(*a.public_key());
    BOOST_TEST(shared_a && shared_b && *shared_a == *shared_b);
    std::array<std::uint8_t, 33> off_curve{};
    off_curve[0] = 0x02;  // x = 0: no point
    BOOST_TEST(a.ecdh(off_curve).error() == crypto::error::invalid_public_key);
}

void make_errors() {
    std::array<std::uint8_t, 31> short_secret{};
    BOOST_TEST(secp::keypair::make(short_secret).error() == crypto::error::invalid_key_size);
    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(secp::keypair::make(zero).error() == crypto::error::invalid_secret_key);
    std::array<std::uint8_t, 32> const order{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                                             0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                                             0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    BOOST_TEST(secp::keypair::make(order).error() == crypto::error::invalid_secret_key);
    // No generator (an audio worklet) is entropy_unavailable to a key pair's caller (m15).
    namespace errc = boost::system::errc;
    BOOST_TEST(secp::detail::seed_error(errc::make_error_code(errc::not_supported)) ==
               crypto::error::entropy_unavailable);
    BOOST_TEST(secp::detail::seed_error(crypto::error::entropy_unavailable) ==
               crypto::error::entropy_unavailable);
}

void moved_from() {
    auto key = from_byte(0x42);
    secp::keypair moved = std::move(key);
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    BOOST_TEST(key.xonly_public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(key.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign_schnorr(message, aux).error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign_ecdsa(message).error() == crypto::error::invalid_state);
    BOOST_TEST(key.ecdh(*moved.public_key()).error() == crypto::error::invalid_state);
    BOOST_TEST(moved.sign_schnorr(message, aux).has_value());
    // A key pair moved from a moved-from one is empty too (I1).
    secp::keypair again = std::move(key);
    BOOST_TEST(again.public_key().error() == crypto::error::invalid_state);
    std::swap(again, moved);
    BOOST_TEST(moved.public_key().error() == crypto::error::invalid_state);
    key = std::move(again);
    BOOST_TEST(key.sign_schnorr(message, aux).has_value());
}

}  // namespace

int main() {
    schnorr();
    ecdsa();
    ecdh();
    make_errors();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
