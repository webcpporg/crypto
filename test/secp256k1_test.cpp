// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's key pair and verifications: signatures that verify and a
// changed message that does not, ECDSA in low-S compact form, ECDH agreeing between two
// parties, every error of make, a moved-from key pair, and public keys refused in every way
// they can be wrong.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

namespace {

// The uncompressed SEC1 form, 04 || x || y, of a key pair's public key, through libsecp256k1.
std::array<std::uint8_t, 65> uncompressed(secp::keypair const& key) {
    auto const compressed = *key.public_key();
    secp256k1_pubkey parsed{};
    BOOST_TEST(secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, compressed.data(),
                                         compressed.size()) == 1);
    std::array<std::uint8_t, 65> out{};
    std::size_t size = out.size();
    BOOST_TEST(secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &size, &parsed,
                                             SECP256K1_EC_UNCOMPRESSED) == 1);
    return out;
}

// X9.62's hybrid form of an uncompressed key: prefix 06 when y is even, 07 when it is odd,
// which libsecp256k1's parser accepts.
std::array<std::uint8_t, 65> hybrid(std::array<std::uint8_t, 65> key) {
    key[0] = static_cast<std::uint8_t>(0x06U | (key[64] & 1U));
    return key;
}

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
    message[0] ^= 1U;
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
    auto const high = webcpp::test::negate_s(*signature);
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
    // X9.62's hybrid forms, 06 and 07 with y's parity, are refused although libsecp256k1
    // parses them: of 65 bytes, only 04.
    auto const full = uncompressed(key);
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, full).has_value());
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, hybrid(full)).error() ==
               crypto::error::invalid_public_key);
    auto wrong_parity = hybrid(full);
    wrong_parity[0] ^= 1U;
    BOOST_TEST(secp::verify_ecdsa(*signature, hash, wrong_parity).error() ==
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
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 32>{}).error() == crypto::error::invalid_public_key);
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 34>{}).error() == crypto::error::invalid_public_key);
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 66>{}).error() == crypto::error::invalid_public_key);
    // The uncompressed form agrees; the hybrid forms, 06 and 07, are refused.
    auto const full = uncompressed(b);
    BOOST_TEST(a.ecdh(full).has_value() && *a.ecdh(full) == *shared_a);
    BOOST_TEST(a.ecdh(hybrid(full)).error() == crypto::error::invalid_public_key);
}

void make_errors() {
    std::array<std::uint8_t, 31> short_secret{};
    BOOST_TEST(secp::keypair::make(short_secret).error() == crypto::error::invalid_key_size);
    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(secp::keypair::make(zero).error() == crypto::error::invalid_secret_key);
    std::array<std::uint8_t, 32> const order{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    };
    BOOST_TEST(secp::keypair::make(order).error() == crypto::error::invalid_secret_key);
    // No generator (an audio worklet) is entropy_unavailable to a key pair's caller (m15).
    namespace errc = boost::system::errc;
    BOOST_TEST(crypto::detail::secp256k1_seed_error(errc::make_error_code(errc::not_supported)) ==
               crypto::error::entropy_unavailable);
    BOOST_TEST(crypto::detail::secp256k1_seed_error(crypto::error::entropy_unavailable) ==
               crypto::error::entropy_unavailable);
}

// A moved-from key pair is what this case tests.
// NOLINTBEGIN(bugprone-use-after-move)
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

// NOLINTEND(bugprone-use-after-move)

}  // namespace

int main() {
    schnorr();
    ecdsa();
    ecdh();
    make_errors();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
