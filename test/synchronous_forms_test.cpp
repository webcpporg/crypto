// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Each operation's member and free synchronous forms (design D9, R21 to R23) give the same results
// on every curve and on AES-GCM and ChaCha20-Poly1305, since the free form calls the member, or
// both call one worker:
// - make: K::make(bytes) and crypto::make<K>(bytes) give the same key (its secret, or its seal),
//   of the same type, on every key pair, AEAD and public key (P-256's of its coordinates too),
//   secp256k1's with a memory resource; generate: crypto::generate<K>() gives a key pair whose
//   signature verifies.
// - sign: key.sign(scheme, input[, extra]) and crypto::sign(key, scheme, input[, extra]) give the
//   same signature, on every scheme of every curve, secp256k1's hedged ECDSA and BIP340 with
//   auxiliary randomness included, each the same type.
// - verify: pub.verify(scheme, signature, input) and crypto::verify(scheme, signature, input, pub)
//   accept a valid signature and refuse a changed one with invalid_signature, a message and a
//   marker of its digest alike; Ed25519's policy and backend named, on both.
// - agree: key.agree(peer) and crypto::agree(key, peer) give the same secret, on P-256 and
//   secp256k1.
// - seal and open: aead.seal and crypto::seal give the same ciphertext and tag; aead.open and
//   crypto::open open it, and refuse a changed tag with authentication_failed, zeroing the data.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory_resource>
#include <span>
#include <type_traits>

namespace crypto = webcpp::crypto;

namespace {

namespace ed25519 = crypto::curves::ed25519;
namespace p256 = crypto::curves::p256;
namespace secp256k1 = crypto::curves::secp256k1;

using ed25519_keypair = ed25519::basic_keypair<crypto::backends::sodium>;
using p256_keypair = p256::basic_keypair<crypto::backends::bearssl>;
using secp_keypair = secp256k1::basic_keypair<crypto::backends::secp256k1>;
using gcm = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;
using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::sodium>;

/** The message every check signs: "abc". */
constexpr std::array<std::uint8_t, 3> message{'a', 'b', 'c'};

/**
 * A secret key of 32 bytes `base`, `base + 1`, ..., valid on every curve (below each group order).
 *
 * @param base The first byte.
 * @return 32 bytes.
 */
constexpr std::array<std::uint8_t, 32> secret_bytes(std::uint8_t base) {
    std::array<std::uint8_t, 32> made{};
    for (std::size_t i = 0; i < made.size(); ++i) {
        made[i] = static_cast<std::uint8_t>(base + i);
    }
    return made;
}

/** SHA-256 of the message, for the markers. */
std::array<std::uint8_t, 32> digest_of_message() {
    webcpp::hash::sha2_256 hasher;
    hasher.update(message.data(), message.size());
    auto const hashed = hasher.result();
    std::array<std::uint8_t, 32> digest{};
    std::copy_n(hashed.data(), digest.size(), digest.begin());
    return digest;
}

/** Whether two secrets hold the same bytes. */
template <std::size_t N>
bool same_secret(crypto::secret<N> const& left, crypto::secret<N> const& right) {
    return std::ranges::equal(left.bytes(), right.bytes());
}

/**
 * A changed copy of a signature: its last byte flipped.
 *
 * @param signature A signature.
 * @return The changed copy.
 */
template <std::size_t N>
std::array<std::uint8_t, N> changed(std::array<std::uint8_t, N> signature) {
    signature.back() ^= 0x01U;
    return signature;
}

/**
 * A key pair's make, member and free: the same type, and the same key (its secret back).
 *
 * @tparam Keypair A key pair's type.
 */
template <class Keypair>
void make_forms() {
    auto const secret_key = secret_bytes(1);
    auto const member_made = Keypair::make(secret_key);
    auto const free_made = crypto::make<Keypair>(secret_key);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (BOOST_TEST(member_made.has_value()) && BOOST_TEST(free_made.has_value())) {
        BOOST_TEST(same_secret(*free_made->secret(), *member_made->secret()));
    }
}

/**
 * A key pair's generate, free: a key pair whose signature verifies with its own public key.
 *
 * @tparam Keypair A key pair's type.
 * @tparam Scheme One of its schemes.
 * @param scheme The scheme.
 */
template <class Keypair, class Scheme>
void generate_forms(Scheme scheme) {
    auto const generated = crypto::generate<Keypair>();
    static_assert(std::is_same_v<decltype(generated), decltype(Keypair::generate()) const>);
    if (!BOOST_TEST(generated.has_value())) {
        return;
    }
    auto const signature = crypto::sign(*generated, scheme, message);
    auto const public_key = generated->public_key();
    if (BOOST_TEST(signature.has_value()) && BOOST_TEST(public_key.has_value())) {
        BOOST_TEST(public_key->verify(scheme, *signature, message).has_value());
    }
}

/**
 * A key pair's agree, member and free: the same type and the same secret, the peer's agreement
 * with this key pair's public key included.
 *
 * @tparam Keypair P-256's or secp256k1's key pair.
 */
template <class Keypair>
void agree_forms() {
    auto const made = Keypair::make(secret_bytes(1));
    auto const peer = Keypair::make(secret_bytes(2));
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const peer_public = peer->public_key();
    auto const member_agreed = made->agree(*peer_public);
    auto const free_agreed = crypto::agree(*made, *peer_public);
    static_assert(std::is_same_v<decltype(free_agreed), decltype(member_agreed)>);
    if (BOOST_TEST(member_agreed.has_value()) && BOOST_TEST(free_agreed.has_value())) {
        BOOST_TEST(same_secret(*free_agreed, *member_agreed));
        BOOST_TEST(same_secret(*crypto::agree(*peer, *public_key), *member_agreed));
    }
}

/**
 * A signature and a changed copy of it, verified by a public key's verify and by
 * crypto::verify: both accept the first and refuse the second with invalid_signature.
 *
 * @tparam Scheme The scheme.
 * @tparam PublicKey The public key's type.
 * @tparam Input A message or a marker.
 * @param scheme The scheme.
 * @param signature A valid signature of `input`.
 * @param input The message or the marker.
 * @param public_key The signer's public key.
 */
template <class Scheme, class PublicKey, class Input>
void verify_forms(Scheme scheme, std::array<std::uint8_t, 64> const& signature, Input const& input,
                  PublicKey const& public_key) {
    BOOST_TEST(public_key.verify(scheme, signature, input).has_value());
    BOOST_TEST(crypto::verify(scheme, signature, input, public_key).has_value());
    auto const wrong = changed(signature);
    BOOST_TEST(public_key.verify(scheme, wrong, input).error() == crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(scheme, wrong, input, public_key).error() ==
               crypto::error::invalid_signature);
}

/** Ed25519: sign and verify, member and free; Ed25519's policy and backend named on both. */
void ed25519_forms() {
    auto const made = ed25519_keypair::make(secret_bytes(1));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const member_signed = made->sign(crypto::eddsa, message);
    auto const free_signed = crypto::sign(*made, crypto::eddsa, message);
    static_assert(std::is_same_v<decltype(free_signed), decltype(member_signed)>);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(member_signed.has_value()) ||
        !BOOST_TEST(free_signed.has_value())) {
        return;
    }
    BOOST_TEST(*free_signed == *member_signed);
    verify_forms(crypto::eddsa, *member_signed, message, *public_key);
    BOOST_TEST(public_key
                   ->verify<crypto::backends::sodium>(crypto::eddsa, *member_signed, message,
                                                      ed25519::strict)
                   .has_value());
    BOOST_TEST(crypto::verify<crypto::backends::sodium>(crypto::eddsa, *member_signed, message,
                                                        *public_key, ed25519::strict)
                   .has_value());
    // A signature of another size, a key's 32 bytes given where the signature goes.
    BOOST_TEST(public_key->verify(crypto::eddsa, public_key->bytes(), message).error() ==
               crypto::error::invalid_signature);
}

/** P-256: sign and verify, member and free, of a message and of a marker of its digest. */
void p256_forms() {
    auto const made = p256_keypair::make(secret_bytes(1));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const digest = digest_of_message();
    auto const member_signed = made->sign(crypto::ecdsa_sha256, message);
    auto const free_signed = crypto::sign(*made, crypto::ecdsa_sha256, message);
    auto const free_prehashed =
        crypto::sign(*made, crypto::ecdsa_sha256, crypto::prehashed{digest});
    static_assert(std::is_same_v<decltype(free_signed), decltype(member_signed)>);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(member_signed.has_value()) ||
        !BOOST_TEST(free_signed.has_value()) || !BOOST_TEST(free_prehashed.has_value())) {
        return;
    }
    // RFC 6979's nonce: the same key and input give the same signature.
    BOOST_TEST(*free_signed == *member_signed);
    BOOST_TEST(*free_prehashed == *member_signed);
    verify_forms(crypto::ecdsa_sha256, *member_signed, message, *public_key);
    verify_forms(crypto::ecdsa_sha256, *member_signed, crypto::prehashed{digest}, *public_key);
}

/**
 * A member's result and the free form's: the same type, both values, and equal values.
 *
 * @tparam Member The member's result type.
 * @tparam Free The free form's result type.
 * @param member The member's result.
 * @param free The free form's result.
 */
template <class Member, class Free>
void same_result(Member const& member, Free const& free) {
    static_assert(std::is_same_v<Free, Member>);
    if (BOOST_TEST(member.has_value()) && BOOST_TEST(free.has_value())) {
        BOOST_TEST(*free == *member);
    }
}

/** secp256k1: every sign, member and free, the same signatures and types. */
void secp256k1_sign_forms() {
    auto const made = secp_keypair::make(secret_bytes(1));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const digest = digest_of_message();
    std::array<std::uint8_t, 32> const extra = secret_bytes(7);
    auto const ecdsa = made->sign(crypto::ecdsa_sha256, message);
    same_result(ecdsa, crypto::sign(*made, crypto::ecdsa_sha256, message));
    same_result(ecdsa, crypto::sign(*made, crypto::ecdsa_sha256, crypto::prehashed{digest}));
    same_result(made->sign(crypto::ecdsa_sha256, message, extra),
                crypto::sign(*made, crypto::ecdsa_sha256, message, extra));
    same_result(made->sign(crypto::ecdsa_sha256_recoverable, message),
                crypto::sign(*made, crypto::ecdsa_sha256_recoverable, message));
    same_result(made->sign(crypto::schnorr, message, extra),
                crypto::sign(*made, crypto::schnorr, message, extra));
}

/**
 * The public keys' make, member and free, on every curve (P-256's of a point and of its
 * coordinates), and secp256k1's key pair make and generate with a memory resource.
 */
void public_key_and_resource_forms() {
    auto const ed25519_made = ed25519_keypair::make(secret_bytes(1));
    auto const p256_made = p256_keypair::make(secret_bytes(1));
    auto const secp_made = secp_keypair::make(secret_bytes(1));
    if (!BOOST_TEST(ed25519_made.has_value()) || !BOOST_TEST(p256_made.has_value()) ||
        !BOOST_TEST(secp_made.has_value())) {
        return;
    }
    auto const ed25519_bytes = ed25519_made->public_key()->bytes();
    same_result(ed25519::public_key::make(ed25519_bytes),
                crypto::make<ed25519::public_key>(ed25519_bytes));

    using p256_public_key = p256::basic_public_key<crypto::backends::bearssl>;
    auto const point = p256_made->public_key()->uncompressed();
    auto const member_point = p256_public_key::make(point);
    auto const free_point = crypto::make<p256_public_key>(point);
    static_assert(std::is_same_v<decltype(free_point), decltype(member_point)>);
    std::span<std::uint8_t const, 32> const x(point.data() + 1, 32);
    std::span<std::uint8_t const, 32> const y(point.data() + 33, 32);
    auto const free_coordinates = crypto::make<p256_public_key>(x, y);
    if (BOOST_TEST(member_point.has_value()) && BOOST_TEST(free_point.has_value()) &&
        BOOST_TEST(free_coordinates.has_value())) {
        BOOST_TEST(free_point->uncompressed() == member_point->uncompressed());
        BOOST_TEST(free_coordinates->uncompressed() == point);
    }

    auto const compressed = secp_made->public_key()->compressed();
    same_result(secp256k1::public_key::make(compressed),
                crypto::make<secp256k1::public_key>(compressed));

    std::pmr::memory_resource* const resource = std::pmr::new_delete_resource();
    auto const member_made = secp_keypair::make(secret_bytes(1), resource);
    auto const free_made = crypto::make<secp_keypair>(secret_bytes(1), resource);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (BOOST_TEST(member_made.has_value()) && BOOST_TEST(free_made.has_value())) {
        BOOST_TEST(same_secret(*free_made->secret(), *member_made->secret()));
    }
    auto const generated = crypto::generate<secp_keypair>(resource);
    static_assert(
        std::is_same_v<decltype(generated), decltype(secp_keypair::generate(resource)) const>);
    BOOST_TEST(generated.has_value());
}

/** secp256k1: both verify schemes, member and free, ECDSA of a marker and Schnorr drawn too. */
void secp256k1_verify_forms() {
    auto const made = secp_keypair::make(secret_bytes(1));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    std::array<std::uint8_t, 32> const extra = secret_bytes(7);
    auto const ecdsa = made->sign(crypto::ecdsa_sha256, message);
    auto const hedged = made->sign(crypto::ecdsa_sha256, message, extra);
    auto const schnorr = made->sign(crypto::schnorr, message, extra);
    // BIP340's auxiliary randomness drawn by the call: another signature.
    auto const drawn = crypto::sign(*made, crypto::schnorr, message);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(ecdsa.has_value()) ||
        !BOOST_TEST(hedged.has_value()) || !BOOST_TEST(schnorr.has_value()) ||
        !BOOST_TEST(drawn.has_value())) {
        return;
    }
    auto const digest = digest_of_message();
    verify_forms(crypto::ecdsa_sha256, *ecdsa, message, *public_key);
    verify_forms(crypto::ecdsa_sha256, *hedged, crypto::prehashed{digest}, *public_key);
    verify_forms(crypto::schnorr, *schnorr, message, *public_key);
    verify_forms(crypto::schnorr, *drawn, message, *public_key);
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr, message, public_key->xonly()).has_value());
    BOOST_TEST(public_key->verify<crypto::backends::secp256k1>(crypto::schnorr, *schnorr, message)
                   .has_value());
    // Each scheme refuses the other's signature.
    BOOST_TEST(public_key->verify(crypto::schnorr, *ecdsa, message).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(public_key->verify(crypto::ecdsa_sha256, *schnorr, message).error() ==
               crypto::error::invalid_signature);
}

/**
 * An AEAD's make, seal and open, member and free: the same ciphertext and tag, and the same
 * refusal of a changed tag.
 *
 * @tparam Aead `gcm` or `chacha`.
 */
template <class Aead>
void aead_forms() {
    std::array<std::uint8_t, Aead::key_size> key{};
    std::ranges::copy(secret_bytes(3), key.begin());
    std::array<std::uint8_t, Aead::iv_size> const iv{9};
    std::array<std::uint8_t, 4> const additional_data{'h', 'e', 'a', 'd'};
    auto member_made = Aead::make(key);
    auto free_made = crypto::make<Aead>(key);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (!BOOST_TEST(member_made.has_value()) || !BOOST_TEST(free_made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 24> member_data{1, 2, 3};
    std::array<std::uint8_t, 24> free_data = member_data;
    auto const member_tag = member_made->seal(iv, additional_data, member_data);
    auto const free_tag = crypto::seal(*free_made, iv, additional_data, free_data);
    static_assert(std::is_same_v<decltype(free_tag), decltype(member_tag)>);
    if (!BOOST_TEST(member_tag.has_value()) || !BOOST_TEST(free_tag.has_value())) {
        return;
    }
    BOOST_TEST(*free_tag == *member_tag);
    BOOST_TEST(free_data == member_data);

    auto const tag = std::span<std::uint8_t const>(member_tag->data(), member_tag->size());
    auto opened_by_member = member_data;
    BOOST_TEST(member_made->open(iv, additional_data, opened_by_member, tag).has_value());
    BOOST_TEST(crypto::open(*free_made, iv, additional_data, free_data, tag).has_value());
    BOOST_TEST(free_data == opened_by_member);
    BOOST_TEST(free_data[0] == 1 && free_data[1] == 2 && free_data[2] == 3);

    auto wrong_tag = *member_tag;
    wrong_tag.data()[0] ^= 0x01U;
    auto const wrong = std::span<std::uint8_t const>(wrong_tag.data(), wrong_tag.size());
    std::array<std::uint8_t, 24> sealed{1, 2, 3};
    std::array<std::uint8_t, 24> const zeros{};
    BOOST_TEST(member_made->seal(iv, additional_data, sealed).has_value());
    auto refused_by_member = sealed;
    BOOST_TEST(member_made->open(iv, additional_data, refused_by_member, wrong).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(crypto::open(*free_made, iv, additional_data, sealed, wrong).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(sealed == zeros);
    BOOST_TEST(refused_by_member == zeros);
}

}  // namespace

int main() {
    make_forms<ed25519_keypair>();
    make_forms<p256_keypair>();
    make_forms<secp_keypair>();
    generate_forms<ed25519_keypair>(crypto::eddsa);
    generate_forms<p256_keypair>(crypto::ecdsa_sha256);
    generate_forms<secp_keypair>(crypto::schnorr);
    generate_forms<secp_keypair>(crypto::ecdsa_sha256);
    agree_forms<p256_keypair>();
    agree_forms<secp_keypair>();
    ed25519_forms();
    p256_forms();
    secp256k1_sign_forms();
    secp256k1_verify_forms();
    public_key_and_resource_forms();
    aead_forms<gcm>();
    aead_forms<chacha>();
    return webcpp::test::exit_status(boost::report_errors());
}
