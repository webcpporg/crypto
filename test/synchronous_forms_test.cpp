// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Each operation's member and free synchronous forms (design D9, R21 to R23) give the same results
// on every curve and on AES-GCM, ChaCha20-Poly1305 and XChaCha20-Poly1305, since the free form
// calls the member, or both call one worker:
// - the factories, named by their input (design D3c): K::from_secret(bytes) and
//   crypto::from_secret<K>(bytes) give the same key pair (its secret and its public key back), of
//   the same type, on every curve, secp256k1's with a memory resource; T::from_bytes(bytes) and
//   crypto::from_bytes<T>(bytes) the same public key, on every curve, and P-256's
//   from_coordinates(x, y) the key from_bytes makes of 04 || x || y; C::from_key(key) and
//   crypto::from_key<C>(key) the same AEAD, its seal; generate: crypto::generate<K>() gives a key
//   pair whose signature verifies.
// - sign: key.sign(scheme, input[, extra]) and crypto::sign(key, scheme, input[, extra]) give the
//   same signature, on every scheme of every curve, secp256k1's hedged ECDSA and BIP340 with
//   auxiliary randomness included, each the same type.
// - verify: pub.verify(scheme, signature, input) and crypto::verify(scheme, signature, input, pub)
//   accept a valid signature and refuse a changed one with invalid_signature, a message and a
//   marker of its digest alike; Ed25519's policy and backend named, on both. Both take the
//   signature as its curve's and scheme's type (design R1), so the same arguments go to every
//   form: a std::vector of the signature, made into the type with from_bytes, verifies, and 63 or
//   65 bytes are refused by from_bytes with invalid_signature, on every scheme, secp256k1's
//   x-only key and recover (64 or 66 bytes, and a std::vector) included.
// - agree: key.agree(peer) and crypto::agree(key, peer) give the same secret, on P-256 and
//   secp256k1.
// - seal and open: cipher.seal and crypto::secret_key_encryption::aead::seal give the same
//   ciphertext and tag; cipher.open and secret_key_encryption::aead::open open it, and refuse a
//   changed tag with authentication_failed, zeroing the data (design D11).
// - the size constants are named nonce_size, max_nonce_size and max_associated_data_size (design
//   D11, R22), on the AEADs, the secret box and the public-key box.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
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
#include <vector>

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
using xchacha = crypto::ciphers::xchacha20_poly1305<crypto::backends::sodium>;

// The size constants spell the nonce and the associated data out (design D11, R22).
static_assert(crypto::ciphers::xchacha20_poly1305<>::nonce_size == 24);
static_assert(crypto::ciphers::aes256_gcm::nonce_size == 12);
static_assert(crypto::ciphers::aes256_gcm::max_nonce_size == 128);
static_assert(crypto::secret_key_encryption::secretbox<>::nonce_size == 24);
static_assert(crypto::public_key_encryption::box::nonce_size == 24);
static_assert(crypto::ciphers::xchacha20_poly1305<>::max_associated_data_size == ~std::uint64_t{0});

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
 * Whether two results both hold a value, each checked before it is read, and equal values: two
 * public keys, or two secrets (of their bytes).
 *
 * @param left A result.
 * @param right Another result of the same value type.
 * @return True when both hold a value and the values are equal.
 */
template <class Result>
bool same_values(Result const& left, Result const& right) {
    if (!BOOST_TEST(left.has_value()) || !BOOST_TEST(right.has_value())) {
        return false;
    }
    if constexpr (requires { same_secret(*left, *right); }) {
        return same_secret(*left, *right);
    } else {
        return *left == *right;
    }
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

/**
 * A changed copy of a signature: its last byte flipped.
 *
 * @tparam Signature A signature type.
 * @param signature A signature.
 * @return The changed copy, of the same type.
 */
template <class Signature>
Signature changed(Signature const& signature) {
    auto changed_bytes = signature.bytes();
    changed_bytes.back() ^= 0x01U;
    return Signature::from_bytes(changed_bytes).value();
}

/**
 * A key pair's from_secret, member and free: the same type, and the same key pair (its secret
 * back, and the member's public key).
 *
 * @tparam Keypair A key pair's type.
 */
template <class Keypair>
void from_secret_forms() {
    auto const secret_key = secret_bytes(1);
    auto const member_made = Keypair::from_secret(secret_key);
    auto const free_made = crypto::from_secret<Keypair>(secret_key);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (BOOST_TEST(member_made.has_value()) && BOOST_TEST(free_made.has_value())) {
        BOOST_TEST(same_values(free_made->secret(), member_made->secret()));
        BOOST_TEST(same_values(free_made->public_key(), member_made->public_key()));
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
    auto const made = Keypair::from_secret(secret_bytes(1));
    auto const peer = Keypair::from_secret(secret_bytes(2));
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
 * @tparam Signature The signature's type, the curve's and the scheme's.
 * @tparam PublicKey The public key's type.
 * @tparam Input A message or a marker.
 * @param scheme The scheme.
 * @param signature A valid signature of `input`.
 * @param input The message or the marker.
 * @param public_key The signer's public key.
 */
template <class Scheme, class Signature, class PublicKey, class Input>
void verify_forms(Scheme scheme, Signature const& signature, Input const& input,
                  PublicKey const& public_key) {
    BOOST_TEST(public_key.verify(scheme, signature, input).has_value());
    BOOST_TEST(crypto::verify(scheme, signature, input, public_key).has_value());
    auto const wrong = changed(signature);
    BOOST_TEST(public_key.verify(scheme, wrong, input).error() == crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(scheme, wrong, input, public_key).error() ==
               crypto::error::invalid_signature);
    // The signature as bytes off the wire, a std::vector, made into the type, by its own
    // from_bytes and by crypto::from_bytes.
    std::vector<std::uint8_t> const received(signature.bytes().begin(), signature.bytes().end());
    auto const made = Signature::from_bytes(received);
    same_result(made, crypto::from_bytes<Signature>(received));
    if (BOOST_TEST(made.has_value())) {
        BOOST_TEST(public_key.verify(scheme, *made, input).has_value());
        BOOST_TEST(crypto::verify(scheme, *made, input, public_key).has_value());
    }
    // One byte short (the signature's first 63) and one byte more (a 65th of 0): no signature.
    auto const short_one = std::span<std::uint8_t const>(received).first(63);
    std::vector<std::uint8_t> long_one = received;
    long_one.push_back(0);
    for (auto const sized : {short_one, std::span<std::uint8_t const>(long_one)}) {
        BOOST_TEST(Signature::from_bytes(sized).error() == crypto::error::invalid_signature);
    }
}

/** Ed25519: sign and verify, member and free; Ed25519's policy and backend named on both. */
void ed25519_forms() {
    auto const made = ed25519_keypair::from_secret(secret_bytes(1));
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
    // A key's 32 bytes, where the signature goes, are no signature.
    BOOST_TEST(ed25519::signature::from_bytes(public_key->bytes()).error() ==
               crypto::error::invalid_signature);
}

/** P-256: sign and verify, member and free, of a message and of a marker of its digest. */
void p256_forms() {
    auto const made = p256_keypair::from_secret(secret_bytes(1));
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

/** secp256k1: every sign, member and free, the same signatures and types. */
void secp256k1_sign_forms() {
    auto const made = secp_keypair::from_secret(secret_bytes(1));
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
 * The public keys' from_bytes, member and free, on every curve, P-256's from_coordinates the key
 * from_bytes makes of 04 || x || y, and secp256k1's key pair from_secret and generate with a
 * memory resource.
 */
void public_key_and_resource_forms() {
    auto const ed25519_made = ed25519_keypair::from_secret(secret_bytes(1));
    auto const p256_made = p256_keypair::from_secret(secret_bytes(1));
    auto const secp_made = secp_keypair::from_secret(secret_bytes(1));
    if (!BOOST_TEST(ed25519_made.has_value()) || !BOOST_TEST(p256_made.has_value()) ||
        !BOOST_TEST(secp_made.has_value())) {
        return;
    }
    auto const ed25519_bytes = ed25519_made->public_key()->bytes();
    same_result(ed25519::public_key::from_bytes(ed25519_bytes),
                crypto::from_bytes<ed25519::public_key>(ed25519_bytes));

    using p256_public_key = p256::basic_public_key<crypto::backends::bearssl>;
    auto const point = p256_made->public_key()->uncompressed();
    same_result(p256_public_key::from_bytes(point), crypto::from_bytes<p256_public_key>(point));
    std::span<std::uint8_t const, 32> const x_bytes(point.data() + 1, 32);
    std::span<std::uint8_t const, 32> const y_bytes(point.data() + 33, 32);
    std::array<std::uint8_t, 65> joined{0x04};
    std::ranges::copy(x_bytes, joined.begin() + 1);
    std::ranges::copy(y_bytes, joined.begin() + 33);
    same_result(p256_public_key::from_bytes(joined),
                p256_public_key::from_coordinates(x_bytes, y_bytes));
    BOOST_TEST(
        same_values(p256_public_key::from_coordinates(x_bytes, y_bytes), p256_made->public_key()));

    auto const compressed = secp_made->public_key()->compressed();
    same_result(secp256k1::public_key::from_bytes(compressed),
                crypto::from_bytes<secp256k1::public_key>(compressed));

    std::pmr::memory_resource* const resource = std::pmr::new_delete_resource();
    auto const member_made = secp_keypair::from_secret(secret_bytes(1), resource);
    auto const free_made = crypto::from_secret<secp_keypair>(secret_bytes(1), resource);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (BOOST_TEST(member_made.has_value()) && BOOST_TEST(free_made.has_value())) {
        BOOST_TEST(same_values(free_made->secret(), member_made->secret()));
        BOOST_TEST(same_values(free_made->public_key(), secp_made->public_key()));
    }
    auto const generated = crypto::generate<secp_keypair>(resource);
    static_assert(
        std::is_same_v<decltype(generated), decltype(secp_keypair::generate(resource)) const>);
    BOOST_TEST(generated.has_value());
}

/** secp256k1: both verify schemes, member and free, ECDSA of a marker and Schnorr drawn too. */
void secp256k1_verify_forms() {
    auto const made = secp_keypair::from_secret(secret_bytes(1));
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
    // BIP340's x-only key takes the typed signature too, made from bytes received; 63 bytes are
    // no signature, whatever the key; a signature with 32 bytes that are no point's x is refused
    // for its key.
    std::vector<std::uint8_t> const received(schnorr->bytes().begin(), schnorr->bytes().end());
    auto const received_signature = secp256k1::schnorr_signature::from_bytes(received);
    if (!BOOST_TEST(received_signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::schnorr, *received_signature, message, public_key->xonly())
                   .has_value());
    auto const short_one = std::span<std::uint8_t const>(received).first(63);
    BOOST_TEST(secp256k1::schnorr_signature::from_bytes(short_one).error() ==
               crypto::error::invalid_signature);
    std::array<std::uint8_t, 32> const no_point{};
    BOOST_TEST(crypto::verify(crypto::schnorr, *received_signature, message, no_point).error() ==
               crypto::error::invalid_public_key);
    // Each scheme refuses the other's signature: its type does not compile there (design R1),
    // and its bytes made into the other's type do not verify.
    auto const ecdsa_as_schnorr = secp256k1::schnorr_signature::from_bytes(ecdsa->bytes());
    auto const schnorr_as_ecdsa = secp256k1::ecdsa_signature::from_bytes(schnorr->bytes());
    if (BOOST_TEST(ecdsa_as_schnorr.has_value()) && BOOST_TEST(schnorr_as_ecdsa.has_value())) {
        BOOST_TEST(public_key->verify(crypto::schnorr, *ecdsa_as_schnorr, message).error() ==
                   crypto::error::invalid_signature);
        BOOST_TEST(public_key->verify(crypto::ecdsa_sha256, *schnorr_as_ecdsa, message).error() ==
                   crypto::error::invalid_signature);
    }
}

/**
 * secp256k1's recover takes the recoverable signature as its type: a std::vector of the 65 bytes,
 * made into it, gives the signer's key, and 64 or 66 bytes are refused by from_bytes with
 * invalid_signature.
 */
void secp256k1_recover_sizes() {
    auto const made = secp_keypair::from_secret(secret_bytes(1));
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const public_key = made->public_key();
    auto const recoverable = made->sign(crypto::ecdsa_sha256_recoverable, message);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(recoverable.has_value())) {
        return;
    }
    std::vector<std::uint8_t> const received(recoverable->bytes().begin(),
                                             recoverable->bytes().end());
    auto const received_signature = secp256k1::recoverable_signature::from_bytes(received);
    if (!BOOST_TEST(received_signature.has_value())) {
        return;
    }
    auto const recovered =
        secp256k1::recover(crypto::ecdsa_sha256_recoverable, *received_signature, message);
    if (BOOST_TEST(recovered.has_value())) {
        BOOST_TEST(*recovered == *public_key);
    }
    auto const short_one = std::span<std::uint8_t const>(received).first(64);
    std::vector<std::uint8_t> long_one = received;
    long_one.push_back(0);
    BOOST_TEST(secp256k1::recoverable_signature::from_bytes(short_one).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(secp256k1::recoverable_signature::from_bytes(long_one).error() ==
               crypto::error::invalid_signature);
}

/**
 * An AEAD's from_key, seal and open, member and free: the same ciphertext and tag, and the same
 * refusal of a changed tag.
 *
 * @tparam Aead `gcm`, `chacha` or `xchacha`.
 */
template <class Aead>
void aead_forms() {
    std::array<std::uint8_t, Aead::key_size> key{};
    std::ranges::copy(secret_bytes(3), key.begin());
    std::array<std::uint8_t, Aead::nonce_size> const nonce{9};
    std::array<std::uint8_t, 4> const associated_data{'h', 'e', 'a', 'd'};
    auto member_made = Aead::from_key(key);
    auto free_made = crypto::from_key<Aead>(key);
    static_assert(std::is_same_v<decltype(free_made), decltype(member_made)>);
    if (!BOOST_TEST(member_made.has_value()) || !BOOST_TEST(free_made.has_value())) {
        return;
    }
    std::array<std::uint8_t, 24> member_data{1, 2, 3};
    std::array<std::uint8_t, 24> free_data = member_data;
    auto const member_tag = member_made->seal(nonce, associated_data, member_data);
    auto const free_tag =
        crypto::secret_key_encryption::aead::seal(*free_made, nonce, associated_data, free_data);
    static_assert(std::is_same_v<decltype(free_tag), decltype(member_tag)>);
    if (!BOOST_TEST(member_tag.has_value()) || !BOOST_TEST(free_tag.has_value())) {
        return;
    }
    BOOST_TEST(*free_tag == *member_tag);
    BOOST_TEST(free_data == member_data);

    auto const tag = std::span<std::uint8_t const>(member_tag->data(), member_tag->size());
    auto opened_by_member = member_data;
    BOOST_TEST(member_made->open(nonce, associated_data, opened_by_member, tag).has_value());
    BOOST_TEST(crypto::secret_key_encryption::aead::open(*free_made, nonce, associated_data,
                                                         free_data, tag)
                   .has_value());
    BOOST_TEST(free_data == opened_by_member);
    BOOST_TEST(free_data[0] == 1 && free_data[1] == 2 && free_data[2] == 3);

    auto wrong_tag = *member_tag;
    wrong_tag.data()[0] ^= 0x01U;
    auto const wrong = std::span<std::uint8_t const>(wrong_tag.data(), wrong_tag.size());
    std::array<std::uint8_t, 24> sealed{1, 2, 3};
    std::array<std::uint8_t, 24> const zeros{};
    BOOST_TEST(member_made->seal(nonce, associated_data, sealed).has_value());
    auto refused_by_member = sealed;
    BOOST_TEST(member_made->open(nonce, associated_data, refused_by_member, wrong).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(
        crypto::secret_key_encryption::aead::open(*free_made, nonce, associated_data, sealed, wrong)
            .error() == crypto::error::authentication_failed);
    BOOST_TEST(sealed == zeros);
    BOOST_TEST(refused_by_member == zeros);
}

}  // namespace

int main() {
    from_secret_forms<ed25519_keypair>();
    from_secret_forms<p256_keypair>();
    from_secret_forms<secp_keypair>();
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
    secp256k1_recover_sizes();
    public_key_and_resource_forms();
    aead_forms<gcm>();
    aead_forms<chacha>();
    aead_forms<xchacha>();
    return webcpp::test::exit_status(boost::report_errors());
}
