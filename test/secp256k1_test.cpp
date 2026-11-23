// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's key pair, key.sign with crypto::schnorr, crypto::ecdsa_sha256 and
// crypto::ecdsa_sha256_recoverable, each giving its own type (schnorr_signature, ecdsa_signature,
// recoverable_signature), and crypto::verify: signatures that verify and a changed message that
// does not; each type made from bytes received as a std::vector, verified (recovered, for the
// recoverable one) through the key's verify and crypto::verify, and refused by from_bytes at one
// byte fewer or more; Schnorr's auxiliary randomness given and drawn; ECDSA's message hashed
// inside, a sighash signed as libsecp256k1 signs it, hedged signing, low S, the empty message;
// Schnorr verified against the typed public key and its x-only bytes alike; the secret key given
// back by secret(), which makes the same key pair again; agree, agree_hashed and agree_point
// agreeing between two parties, agree_hashed as libsecp256k1's own secp256k1_ecdh; every error of
// from_secret, a moved-from key pair, and public keys refused in every way they can be wrong.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

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

// A signature of the type `Signature` from its bytes, as one received is made.
template <class Signature>
Signature typed(std::span<std::uint8_t const> signature_bytes) {
    auto made = Signature::from_bytes(signature_bytes);
    BOOST_TEST(made.has_value());
    return made ? *made : Signature{};
}

// The uncompressed SEC1 form, 04 || x || y, of a key pair's public key, through libsecp256k1.
std::array<std::uint8_t, 65> uncompressed(secp::keypair const& key) {
    auto const compressed = key.public_key()->compressed();
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
    return *secp::keypair::from_secret(secret);
}

void schnorr() {
    auto const key = from_byte(0x42);
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    std::array<std::uint8_t, 32> const aux{};
    auto const signature = key.sign(crypto::schnorr, message, aux);
    auto const public_key = key.public_key();
    if (!BOOST_TEST(signature && public_key)) {
        return;
    }
    // The typed key and its 32 x-only bytes verify alike.
    auto const xonly = public_key->xonly();
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, xonly).has_value());
    auto flipped_bytes = signature->bytes();
    flipped_bytes[0] ^= 1U;
    auto const flipped = typed<secp::schnorr_signature>(flipped_bytes);
    BOOST_TEST(crypto::verify(crypto::schnorr, flipped, message, *public_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::schnorr, flipped, message, xonly).error() ==
               crypto::error::invalid_signature);
    message[0] ^= 1U;
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, xonly).error() ==
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
    auto const public_key = key.public_key();
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
    auto const parsed = key.public_key();
    auto const xonly = parsed->xonly();
    auto const schnorr_empty = key.sign(crypto::schnorr, empty, aux);
    auto const drawn_empty = key.sign(crypto::schnorr, empty);
    auto const ecdsa_empty = key.sign(crypto::ecdsa_sha256, empty);
    if (!BOOST_TEST(parsed && schnorr_empty && drawn_empty && ecdsa_empty)) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_empty, empty, xonly).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *drawn_empty, empty, *parsed).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_empty, other, xonly).error() ==
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
    auto const public_key = key->public_key();
    BOOST_TEST(signature && public_key);
    BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, *public_key).has_value());
    auto const other = secp::keypair::generate();
    BOOST_TEST(other.has_value() && *other->public_key() != *public_key);
}

void ecdsa() {
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x99);
    auto const signature = key.sign(crypto::ecdsa_sha256, crypto::prehashed{hash});
    auto const public_key = key.public_key();
    if (!BOOST_TEST(signature && public_key)) {
        return;
    }
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{hash}, *public_key)
            .has_value());
    // Low-S: s is at most half the group order, so its first byte is below 0x80.
    BOOST_TEST(signature->bytes()[32] < 0x80);
    BOOST_TEST(secp::is_low_s(*signature));
    // The high-S form of the same signature is refused, as libsecp256k1's verify refuses it.
    auto const high = typed<secp::ecdsa_signature>(webcpp::test::negate_s(signature->bytes()));
    BOOST_TEST(!secp::is_low_s(high));
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, high, crypto::prehashed{hash}, *public_key).error() ==
        crypto::error::invalid_signature);
    std::array<std::uint8_t, 64> overflow{};
    overflow.fill(0xff);  // r and s not below the order: the compact parser refuses it
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, typed<secp::ecdsa_signature>(overflow),
                              crypto::prehashed{hash}, *public_key)
                   .error() == crypto::error::invalid_signature);
    // The uncompressed form parses to the same key, which verifies.
    auto const full = secp::public_key::from_bytes(uncompressed(key));
    BOOST_TEST(full.has_value() &&
               crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{hash}, *full)
                   .has_value());
}

// The public key of ECDSA's verification is made first: every way 33 or 65 bytes can be no
// key is refused there.
void parse_refusals() {
    auto const key = from_byte(0x24);
    std::array<std::uint8_t, 34> const wrong_size{};
    BOOST_TEST(secp::public_key::from_bytes(wrong_size).error() ==
               crypto::error::invalid_public_key);
    auto bad_prefix = key.public_key()->compressed();
    bad_prefix[0] = 0x05;
    BOOST_TEST(secp::public_key::from_bytes(bad_prefix).error() ==
               crypto::error::invalid_public_key);
    // X9.62's hybrid forms, 06 and 07 with y's parity, are refused although libsecp256k1
    // parses them: of 65 bytes, only 04.
    auto const full = uncompressed(key);
    BOOST_TEST(secp::public_key::from_bytes(full).has_value());
    BOOST_TEST(secp::public_key::from_bytes(hybrid(full)).error() ==
               crypto::error::invalid_public_key);
    auto wrong_parity = hybrid(full);
    wrong_parity[0] ^= 1U;
    BOOST_TEST(secp::public_key::from_bytes(wrong_parity).error() ==
               crypto::error::invalid_public_key);
}

// A 32-byte message under ecdsa_sha256 is hashed, never read as a digest: its signature is the
// signature of its SHA-256, not of its own bytes marked as a digest.
void ecdsa_message_is_hashed() {
    auto const key = from_byte(0x24);
    auto const public_key = key.public_key();
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
    BOOST_TEST(
        recoverable.has_value() &&
        std::ranges::equal(std::span(recoverable->bytes()).first<64>(), of_message->bytes()));
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
    auto const public_key = key.public_key();
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
    BOOST_TEST(signature->bytes() == compact);
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{digest}, *public_key)
            .has_value());
}

// Hedged ECDSA differs from the plain one and verifies, of a message as of a digest.
void hedged_differs() {
    auto const key = from_byte(0x24);
    auto const public_key = key.public_key();
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

// A signature's bytes as they are received, in a vector.
template <class Signature>
std::vector<std::uint8_t> received_bytes(Signature const& signature) {
    return {signature.bytes().begin(), signature.bytes().end()};
}

// Bytes of one byte fewer or more than `Signature` holds are no signature: from_bytes refuses them,
// before any verify or recover.
template <class Signature>
void other_sizes_refused(std::vector<std::uint8_t> const& received) {
    for (std::size_t const size : {Signature::size - 1, Signature::size + 1}) {
        auto resized = received;
        resized.resize(size);
        BOOST_TEST(Signature::from_bytes(resized).error() == crypto::error::invalid_signature);
    }
}

// ECDSA's and BIP340's types from 64 bytes received in a vector, each verified through the key's
// verify and crypto::verify, BIP340's against the x-only key too; 63 and 65 bytes refused.
void verified_from_vectors() {
    auto const key = from_byte(0x24);
    auto const public_key = key.public_key();
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const ecdsa_signed = key.sign(crypto::ecdsa_sha256, message);
    auto const schnorr_signed = key.sign(crypto::schnorr, message);
    if (!BOOST_TEST(public_key && ecdsa_signed && schnorr_signed)) {
        return;
    }
    auto const ecdsa_bytes = received_bytes(*ecdsa_signed);
    auto const ecdsa_made = secp::ecdsa_signature::from_bytes(ecdsa_bytes);
    if (BOOST_TEST(ecdsa_made.has_value())) {
        BOOST_TEST(public_key->verify(crypto::ecdsa_sha256, *ecdsa_made, message).has_value());
        BOOST_TEST(
            crypto::verify(crypto::ecdsa_sha256, *ecdsa_made, message, *public_key).has_value());
    }
    other_sizes_refused<secp::ecdsa_signature>(ecdsa_bytes);
    auto const schnorr_bytes = received_bytes(*schnorr_signed);
    auto const schnorr_made = secp::schnorr_signature::from_bytes(schnorr_bytes);
    if (BOOST_TEST(schnorr_made.has_value())) {
        BOOST_TEST(public_key->verify(crypto::schnorr, *schnorr_made, message).has_value());
        BOOST_TEST(
            crypto::verify(crypto::schnorr, *schnorr_made, message, *public_key).has_value());
        BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_made, message, public_key->xonly())
                       .has_value());
    }
    other_sizes_refused<secp::schnorr_signature>(schnorr_bytes);
}

// The recoverable type from 65 bytes received in a vector gives its key to recover; 64 and 66
// bytes refused.
void recovered_from_vector() {
    auto const key = from_byte(0x24);
    auto const public_key = key.public_key();
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const recoverable_signed = key.sign(crypto::ecdsa_sha256_recoverable, message);
    if (!BOOST_TEST(public_key && recoverable_signed)) {
        return;
    }
    auto const recoverable_bytes = received_bytes(*recoverable_signed);
    auto const recoverable_made = secp::recoverable_signature::from_bytes(recoverable_bytes);
    if (BOOST_TEST(recoverable_made.has_value())) {
        auto const recovered =
            secp::recover(crypto::ecdsa_sha256_recoverable, *recoverable_made, message);
        BOOST_TEST(recovered.has_value() && *recovered == *public_key);
    }
    other_sizes_refused<secp::recoverable_signature>(recoverable_bytes);
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
using message_span = std::span<std::uint8_t const>;
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, secp::ecdsa_signature, message_span,
                                 secp::public_key>);
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, secp::ecdsa_signature,
                                 crypto::prehashed<32>, secp::public_key>);
static_assert(crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, message_span,
                                 std::array<std::uint8_t, 32>>);
static_assert(crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, message_span,
                                 std::span<std::uint8_t const, 32>>);
static_assert(!crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, crypto::prehashed<32>,
                                  std::array<std::uint8_t, 32>>);
// Bytes of another size, or of a size known only at run time, are no x-only key.
static_assert(!crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, message_span,
                                  std::array<std::uint8_t, 33>>);
static_assert(!crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, message_span,
                                  std::span<std::uint8_t const>>);
// Bytes are no secp256k1 ECDSA key: ECDSA never infers its curve from a number of bytes.
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp::ecdsa_signature, message_span,
                                  std::array<std::uint8_t, 33>>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp::ecdsa_signature, message_span,
                                  secp::keypair>);
// The typed key verifies Schnorr beside its 32 x-only bytes; a marker is no Schnorr input.
static_assert(
    crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, message_span, secp::public_key>);
static_assert(!crypto::can_verify<crypto::schnorr_t, secp::schnorr_signature, crypto::prehashed<32>,
                                  secp::public_key>);
// Each scheme verifies its own type alone: bytes, and the other scheme's type, are none
// (design R1), the recoverable one included, which recover takes.
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp::schnorr_signature, message_span,
                                  secp::public_key>);
static_assert(
    !crypto::can_verify<crypto::schnorr_t, secp::ecdsa_signature, message_span, secp::public_key>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, secp::recoverable_signature, message_span,
                                  secp::public_key>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, std::array<std::uint8_t, 64>,
                                  message_span, secp::public_key>);
static_assert(!crypto::can_verify<crypto::schnorr_t, std::array<std::uint8_t, 64>, message_span,
                                  std::array<std::uint8_t, 32>>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::ecdsa_sha256_recoverable,
                                 std::declval<std::span<std::uint8_t const>>())),
                             boost::system::result<secp::recoverable_signature>>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::schnorr, std::declval<std::span<std::uint8_t const>>())),
                             boost::system::result<secp::schnorr_signature>>);
static_assert(
    std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                       crypto::ecdsa_sha256, std::declval<std::span<std::uint8_t const>>())),
                   boost::system::result<secp::ecdsa_signature>>);
// The hedged and the explicit-aux forms give the types too.
static_assert(
    std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                       crypto::ecdsa_sha256, std::declval<std::span<std::uint8_t const>>(),
                       std::declval<std::span<std::uint8_t const, 32>>())),
                   boost::system::result<secp::ecdsa_signature>>);
static_assert(std::is_same_v<decltype(std::declval<secp::keypair const&>().sign(
                                 crypto::schnorr, std::declval<std::span<std::uint8_t const>>(),
                                 std::declval<std::span<std::uint8_t const, 32>>())),
                             boost::system::result<secp::schnorr_signature>>);
static_assert(
    std::is_same_v<decltype(secp::is_low_s(std::declval<secp::ecdsa_signature>())), bool>);

// The three agreements of two key pairs agree; agree is agree_point's x, and agree_hashed is
// libsecp256k1's own secp256k1_ecdh with its default hash; the peer's uncompressed form makes the
// same key, which agrees alike.
void agreements() {
    std::array<std::uint8_t, 32> a_secret{};
    a_secret.fill(0x11);
    auto const a = from_byte(0x11);
    auto const b = from_byte(0x22);
    auto const a_public = a.public_key();
    auto const b_public = b.public_key();
    if (!BOOST_TEST(a_public && b_public)) {
        return;
    }
    auto const x_a = a.agree(*b_public);
    auto const x_b = b.agree(*a_public);
    auto const hashed_a = a.agree_hashed(*b_public);
    auto const hashed_b = b.agree_hashed(*a_public);
    auto const point_a = a.agree_point(*b_public);
    auto const point_b = b.agree_point(*a_public);
    if (!BOOST_TEST(x_a && x_b && hashed_a && hashed_b && point_a && point_b)) {
        return;
    }
    BOOST_TEST(std::ranges::equal(x_a->bytes(), x_b->bytes()));
    BOOST_TEST(std::ranges::equal(hashed_a->bytes(), hashed_b->bytes()));
    BOOST_TEST(std::ranges::equal(point_a->bytes(), point_b->bytes()));
    BOOST_TEST(std::ranges::equal(point_a->bytes().subspan<1, 32>(), x_a->bytes()));
    secp256k1_pubkey peer{};
    auto const b_compressed = b_public->compressed();
    BOOST_TEST_EQ(secp256k1_ec_pubkey_parse(secp256k1_context_static, &peer, b_compressed.data(),
                                            b_compressed.size()),
                  1);
    std::array<std::uint8_t, 32> reference{};
    BOOST_TEST_EQ(secp256k1_ecdh(secp256k1_context_static, reference.data(), &peer, a_secret.data(),
                                 nullptr, nullptr),
                  1);
    BOOST_TEST(std::ranges::equal(hashed_a->bytes(), reference));
    auto const full = secp::public_key::from_bytes(uncompressed(b));
    if (!BOOST_TEST(full.has_value())) {
        return;
    }
    BOOST_TEST(*full == *b_public);
    auto const x_full = a.agree(*full);
    BOOST_TEST(x_full && std::ranges::equal(x_full->bytes(), x_a->bytes()));
}

// secret() gives back the 32 bytes make took, which make the same key pair again: the same public
// key, and a signature of one verifies under the other's key.
void secret_round_trip() {
    std::array<std::uint8_t, 32> secret_key{};
    for (std::size_t i = 0; i < secret_key.size(); ++i) {
        secret_key[i] = static_cast<std::uint8_t>(0x40U + i);
    }
    auto const key = secp::keypair::from_secret(secret_key);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const exported = key->secret();
    if (!BOOST_TEST(exported.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(exported->bytes(), secret_key));
    auto const again = secp::keypair::from_secret(exported->bytes());
    if (!BOOST_TEST(again.has_value())) {
        return;
    }
    BOOST_TEST(*again->public_key() == *key->public_key());
    std::array<std::uint8_t, 3> const message{'a', 'b', 'c'};
    auto const signature = again->sign(crypto::schnorr, message);
    BOOST_TEST(
        signature.has_value() &&
        crypto::verify(crypto::schnorr, *signature, message, *key->public_key()).has_value());
}

// A public key's three byte forms: the uncompressed one is libsecp256k1's, the compressed one and
// the uncompressed one carry the x-only one; both SEC1 forms make the same key back, and the
// x-only form, which is no SEC1 form, is refused.
void byte_forms() {
    auto const key = from_byte(0x24);
    auto const public_key = key.public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return;
    }
    auto const compressed = public_key->compressed();
    auto const full = public_key->uncompressed();
    auto const xonly = public_key->xonly();
    BOOST_TEST(std::ranges::equal(full, uncompressed(key)));
    BOOST_TEST(compressed[0] == 0x02 || compressed[0] == 0x03);
    BOOST_TEST(std::ranges::equal(std::span(compressed).subspan<1>(), xonly));
    BOOST_TEST(std::ranges::equal(std::span(full).subspan<1, 32>(), xonly));
    BOOST_TEST(*secp::public_key::from_bytes(compressed) == *public_key);
    BOOST_TEST(*secp::public_key::from_bytes(full) == *public_key);
    BOOST_TEST(secp::public_key::from_bytes(xonly).error() == crypto::error::invalid_public_key);
}

void make_errors() {
    std::array<std::uint8_t, 31> short_secret{};
    BOOST_TEST(secp::keypair::from_secret(short_secret).error() == crypto::error::invalid_key_size);
    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(secp::keypair::from_secret(zero).error() == crypto::error::invalid_secret_key);
    std::array<std::uint8_t, 32> const order{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    };
    BOOST_TEST(secp::keypair::from_secret(order).error() == crypto::error::invalid_secret_key);
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
    BOOST_TEST(key.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(key.secret().error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign(crypto::schnorr, message, aux).error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign(crypto::schnorr, message).error() == crypto::error::invalid_state);
    BOOST_TEST(key.sign(crypto::ecdsa_sha256, message).error() == crypto::error::invalid_state);
    BOOST_TEST(key.agree(*moved.public_key()).error() == crypto::error::invalid_state);
    BOOST_TEST(key.agree_hashed(*moved.public_key()).error() == crypto::error::invalid_state);
    BOOST_TEST(key.agree_point(*moved.public_key()).error() == crypto::error::invalid_state);
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
    verified_from_vectors();
    recovered_from_vector();
    agreements();
    secret_round_trip();
    byte_forms();
    make_errors();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
