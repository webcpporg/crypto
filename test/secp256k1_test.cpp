// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's key pair, key.sign with crypto::schnorr, crypto::ecdsa_sha256 and
// crypto::ecdsa_sha256_recoverable, and crypto::verify: signatures that verify and a changed
// message that does not; Schnorr's auxiliary randomness given and drawn; ECDSA's message hashed
// inside, a sighash signed as libsecp256k1 signs it, hedged signing, low S, the empty message;
// ECDH agreeing between two parties, every error of make, a moved-from key pair, and public keys
// refused in every way they can be wrong.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

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
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_UNCOMPRESSED;
    BOOST_TEST(secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &size, &parsed,
                                             flags) == 1);
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
    auto const signature = key.sign(crypto::schnorr, message, aux);
    auto const public_key = key.xonly_public_key();
    if (!BOOST_TEST(signature && public_key)) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).has_value());
    auto flipped = *signature;
    flipped[0] ^= 1U;
    BOOST_TEST(crypto::verify(crypto::schnorr, flipped, message, *public_key).error() ==
               crypto::error::invalid_signature);
    message[0] ^= 1U;
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).error() ==
               crypto::error::invalid_signature);
    std::array<std::uint8_t, 32> const not_a_point{};  // x = 0 has no point
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, not_a_point).error() ==
               crypto::error::invalid_public_key);
}

// sign(schnorr, message) draws its auxiliary randomness: two signatures of one message differ,
// and both verify.
void schnorr_draws_aux() {
    auto const key = from_byte(0x42);
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    auto const first = key.sign(crypto::schnorr, message);
    auto const second = key.sign(crypto::schnorr, message);
    auto const public_key = key.xonly_public_key();
    if (!BOOST_TEST(first && second && public_key)) {
        return;
    }
    BOOST_TEST(*first != *second);
    BOOST_TEST(crypto::verify(crypto::schnorr, *first, message, *public_key).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *second, message, *public_key).has_value());
}

// The empty message is a message under every scheme: it signs and verifies, and another
// message does not verify its signature.
void empty_message() {
    auto const key = from_byte(0x42);
    std::span<std::uint8_t const> const empty{};
    std::array<std::uint8_t, 32> const aux{};
    std::array<std::uint8_t, 1> const other{'x'};
    auto const xonly = key.xonly_public_key();
    auto const parsed = secp::parse_public_key(*key.public_key());
    auto const schnorr_empty = key.sign(crypto::schnorr, empty, aux);
    auto const drawn_empty = key.sign(crypto::schnorr, empty);
    auto const ecdsa_empty = key.sign(crypto::ecdsa_sha256, empty);
    if (!BOOST_TEST(xonly && parsed && schnorr_empty && drawn_empty && ecdsa_empty)) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_empty, empty, *xonly).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *drawn_empty, empty, *xonly).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_empty, other, *xonly).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *ecdsa_empty, empty, *parsed).has_value());
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *ecdsa_empty,
                              crypto::prehashed{crypto::detail::sha256_of(empty)}, *parsed)
                   .has_value());
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *ecdsa_empty, other, *parsed).error() ==
               crypto::error::invalid_signature);
    // A vector converts to a message too, of any size.
    std::vector<std::uint8_t> const none;
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *ecdsa_empty, none, *parsed).has_value());
}

// A key pair generated from the system's source signs and verifies as one made from a secret.
void generated() {
    auto const key = secp::keypair::generate();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    std::array<std::uint8_t, 32> message{};
    message.fill(0x29);
    std::array<std::uint8_t, 32> const aux{};
    auto const signature = key->sign(crypto::schnorr, message, aux);
    auto const public_key = key->xonly_public_key();
    BOOST_TEST(signature && public_key);
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).has_value());
    auto const other = secp::keypair::generate();
    BOOST_TEST(other.has_value() && !(*other->xonly_public_key() == *public_key));
}

void ecdsa() {
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x99);
    auto const signature = key.sign(crypto::ecdsa_sha256, crypto::prehashed{hash});
    auto const public_key = secp::parse_public_key(*key.public_key());
    if (!BOOST_TEST(signature && public_key)) {
        return;
    }
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{hash}, *public_key)
            .has_value());
    // Low-S: s is at most half the group order, so its first byte is below 0x80.
    BOOST_TEST((*signature)[32] < 0x80);
    BOOST_TEST(secp::is_low_s(*signature));
    // The high-S form of the same signature is refused, as libsecp256k1's verify refuses it.
    auto const high = webcpp::test::negate_s(*signature);
    BOOST_TEST(!secp::is_low_s(high));
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, high, crypto::prehashed{hash}, *public_key).error() ==
        crypto::error::invalid_signature);
    std::array<std::uint8_t, 64> overflow{};
    overflow.fill(0xff);  // r and s not below the order: the compact parser refuses it
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, overflow, crypto::prehashed{hash}, *public_key)
                   .error() == crypto::error::invalid_signature);
    // The uncompressed form parses to the same key, which verifies.
    auto const full = secp::parse_public_key(uncompressed(key));
    BOOST_TEST(full.has_value() &&
               crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{hash}, *full)
                   .has_value());
}

// The public key of ECDSA's verification is parsed first: every way 33 or 65 bytes can be no
// key is refused there.
void parse_refusals() {
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 34> const wrong_size{};
    BOOST_TEST(secp::parse_public_key(wrong_size).error() == crypto::error::invalid_public_key);
    auto bad_prefix = *key.public_key();
    bad_prefix[0] = 0x05;
    BOOST_TEST(secp::parse_public_key(bad_prefix).error() == crypto::error::invalid_public_key);
    // X9.62's hybrid forms, 06 and 07 with y's parity, are refused although libsecp256k1
    // parses them: of 65 bytes, only 04.
    auto const full = uncompressed(key);
    BOOST_TEST(secp::parse_public_key(full).has_value());
    BOOST_TEST(secp::parse_public_key(hybrid(full)).error() == crypto::error::invalid_public_key);
    auto wrong_parity = hybrid(full);
    wrong_parity[0] ^= 1U;
    BOOST_TEST(secp::parse_public_key(wrong_parity).error() == crypto::error::invalid_public_key);
}

// A 32-byte message under ecdsa_sha256 is hashed, never read as a digest: its signature is the
// signature of its SHA-256, not of its own bytes marked as a digest.
void ecdsa_message_is_hashed() {
    auto const key = from_byte(0x24);
    auto const public_key = secp::parse_public_key(*key.public_key());
    std::array<std::uint8_t, 32> message{};
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>((i * 7) + 1);
    }
    auto const of_message = key.sign(crypto::ecdsa_sha256, message);
    auto const of_digest =
        key.sign(crypto::ecdsa_sha256, crypto::prehashed{crypto::detail::sha256_of(message)});
    auto const of_marker = key.sign(crypto::ecdsa_sha256, crypto::prehashed{message});
    if (!BOOST_TEST(public_key && of_message && of_digest && of_marker)) {
        return;
    }
    BOOST_TEST(*of_message == *of_digest);
    BOOST_TEST(*of_message != *of_marker);
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *of_message, message, *public_key).has_value());
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *of_message, crypto::prehashed{message}, *public_key)
            .error() == crypto::error::invalid_signature);
    // The recoverable signature's r and s are the same as ecdsa_sha256's.
    auto const recoverable = key.sign(crypto::ecdsa_sha256_recoverable, message);
    BOOST_TEST(recoverable.has_value() &&
               std::ranges::equal(std::span(*recoverable).first<64>(), *of_message));
}

// A sighash, a digest the program computed, signed with prehashed under ecdsa_sha256, is the
// signature libsecp256k1's own secp256k1_ecdsa_sign makes of it, and verifies.
void sighash() {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x24);
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        digest[i] = static_cast<std::uint8_t>(0xa0U ^ i);
    }
    auto const signature = key.sign(crypto::ecdsa_sha256, crypto::prehashed{digest});
    auto const public_key = secp::parse_public_key(*key.public_key());
    if (!BOOST_TEST(signature && public_key)) {
        return;
    }
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    secp256k1_context* const context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!BOOST_TEST(context != nullptr)) {
        return;
    }
    secp256k1_ecdsa_signature reference{};
    BOOST_TEST_EQ(
        secp256k1_ecdsa_sign(context, &reference, digest.data(), secret.data(), nullptr, nullptr),
        1);
    std::array<std::uint8_t, 64> compact{};
    secp256k1_ecdsa_signature_serialize_compact(context, compact.data(), &reference);
    secp256k1_context_destroy(context);
    BOOST_TEST(*signature == compact);
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{digest}, *public_key)
            .has_value());
}

// Hedged ECDSA differs from the plain one and verifies, of a message as of a digest.
void hedged_differs() {
    auto const key = from_byte(0x24);
    auto const public_key = secp::parse_public_key(*key.public_key());
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 32> entropy{};
    entropy.fill(0x5a);
    auto const plain = key.sign(crypto::ecdsa_sha256, message);
    auto const hedged = key.sign(crypto::ecdsa_sha256, message, entropy);
    auto const digest = crypto::detail::sha256_of(message);
    auto const hedged_digest = key.sign(crypto::ecdsa_sha256, crypto::prehashed{digest}, entropy);
    if (!BOOST_TEST(public_key && plain && hedged && hedged_digest)) {
        return;
    }
    BOOST_TEST(*hedged != *plain);
    BOOST_TEST(*hedged == *hedged_digest);
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *hedged, message, *public_key).has_value());
}

// The pairs that go together, and those that do not.
static_assert(
    crypto::can_sign<secp::keypair, crypto::ecdsa_sha256_t, std::span<std::uint8_t const>>);
static_assert(crypto::can_sign<secp::keypair, crypto::ecdsa_sha256_t, crypto::prehashed<32>>);
static_assert(
    crypto::can_sign<secp::keypair, crypto::ecdsa_sha256_recoverable_t, crypto::prehashed<32>>);
static_assert(crypto::can_sign<secp::keypair, crypto::schnorr_t, std::vector<std::uint8_t>>);
static_assert(!crypto::can_sign<secp::keypair, crypto::schnorr_t, crypto::prehashed<32>>);
static_assert(!crypto::can_sign<secp::keypair, crypto::ecdsa_sha256_t, crypto::prehashed<48>>);
static_assert(!crypto::can_sign<secp::keypair, crypto::eddsa_t, std::span<std::uint8_t const>>);
static_assert(
    !crypto::can_sign<secp::public_key, crypto::ecdsa_sha256_t, std::span<std::uint8_t const>>);
static_assert(
    crypto::can_verify<crypto::ecdsa_sha256_t, std::span<std::uint8_t const>, secp::public_key>);
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, crypto::prehashed<32>, secp::public_key>);
static_assert(crypto::can_verify<crypto::schnorr_t, std::span<std::uint8_t const>,
                                 std::array<std::uint8_t, 32>>);
static_assert(crypto::can_verify<crypto::schnorr_t, std::span<std::uint8_t const>,
                                 std::span<std::uint8_t const, 32>>);
static_assert(
    !crypto::can_verify<crypto::schnorr_t, crypto::prehashed<32>, std::array<std::uint8_t, 32>>);
// Bytes of another size, or of a size known only at run time, are no x-only key.
static_assert(!crypto::can_verify<crypto::schnorr_t, std::span<std::uint8_t const>,
                                  std::array<std::uint8_t, 33>>);
static_assert(!crypto::can_verify<crypto::schnorr_t, std::span<std::uint8_t const>,
                                  std::span<std::uint8_t const>>);
// Bytes are no secp256k1 ECDSA key: ECDSA never infers its curve from a number of bytes.
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, std::span<std::uint8_t const>,
                                  std::array<std::uint8_t, 33>>);
static_assert(
    !crypto::can_verify<crypto::ecdsa_sha256_t, std::span<std::uint8_t const>, secp::keypair>);
static_assert(
    !crypto::can_verify<crypto::schnorr_t, std::span<std::uint8_t const>, secp::public_key>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::ecdsa_sha256_recoverable,
                                 std::declval<std::span<std::uint8_t const>>())),
                             boost::system::result<std::array<std::uint8_t, 65>>>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::schnorr, std::declval<std::span<std::uint8_t const>>())),
                             boost::system::result<std::array<std::uint8_t, 64>>>);
static_assert(
    std::is_same_v<decltype(secp::is_low_s(std::declval<std::array<std::uint8_t, 64>>())), bool>);

void ecdh() {
    auto const a = from_byte(0x11);
    auto const b = from_byte(0x22);
    auto const shared_a = a.ecdh(*b.public_key());
    auto const shared_b = b.ecdh(*a.public_key());
    BOOST_TEST(shared_a && shared_b && std::ranges::equal(shared_a->bytes(), shared_b->bytes()));
    std::array<std::uint8_t, 33> off_curve{};
    off_curve[0] = 0x02;  // x = 0: no point
    BOOST_TEST(a.ecdh(off_curve).error() == crypto::error::invalid_public_key);
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 32>{}).error() == crypto::error::invalid_public_key);
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 34>{}).error() == crypto::error::invalid_public_key);
    BOOST_TEST(a.ecdh(std::array<std::uint8_t, 66>{}).error() == crypto::error::invalid_public_key);
    // The uncompressed form agrees; the hybrid forms, 06 and 07, are refused.
    auto const full = uncompressed(b);
    auto const shared_full = a.ecdh(full);
    BOOST_TEST(shared_full && shared_a &&
               std::ranges::equal(shared_full->bytes(), shared_a->bytes()));
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
    BOOST_TEST(key.sign(crypto::schnorr, message, aux).error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign(crypto::schnorr, message).error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign(crypto::ecdsa_sha256, message).error() == crypto::error::invalid_state);
    BOOST_TEST(key.ecdh(*moved.public_key()).error() == crypto::error::invalid_state);
    BOOST_TEST(moved.sign(crypto::schnorr, message, aux).has_value());
    // A key pair moved from a moved-from one is empty too (I1).
    secp::keypair again = std::move(key);
    BOOST_TEST(again.public_key().error() == crypto::error::invalid_state);
    std::swap(again, moved);
    BOOST_TEST(moved.public_key().error() == crypto::error::invalid_state);
    key = std::move(again);
    BOOST_TEST(key.sign(crypto::schnorr, message, aux).has_value());
}

// NOLINTEND(bugprone-use-after-move)

}  // namespace

int main() {
    schnorr();
    schnorr_draws_aux();
    empty_message();
    generated();
    ecdsa();
    parse_refusals();
    ecdsa_message_is_hashed();
    sighash();
    hedged_differs();
    ecdh();
    make_errors();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
