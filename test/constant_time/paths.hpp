// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time paths that memcheck (ctgrind_test.cpp) and MemorySanitizer (msan_test.cpp)
// both check, written once against a checker's four primitives, so that the two checkers'
// coverage cannot diverge: a later family adds its path here. A checker is a type with
//
// - `static void mark_secret(std::span<std::uint8_t>)`: the bytes are secret from now on;
// - `static void mark_public(std::span<std::uint8_t const>)`: the bytes are public, as a public
//   key derived from a secret one is;
// - `static std::optional<bool> traced(std::span<std::uint8_t const>)`: whether the secret mark
//   reached some byte of these, so that the path that wrote them is traced; empty when the
//   checker could not read its own shadow, which every check here counts as a failure;
// - `static void verdict(bool const&)`: the verdict, whether a tag matched, must be public, the
//   checker reports it otherwise;
//
// and two facts about its shadow: `exact_subtraction`, whether the mark follows a subtraction's
// carry (memcheck's does, MemorySanitizer's approximation drops it, so that a constant-time
// reduction of a secret to one bit comes out public, msan_test.cpp says more), and
// `reads_destroyed`, whether a destroyed object's bytes can be read back (MemorySanitizer marks
// them by itself, -fsanitize-memory-use-after-dtor). A trace that the shadow cannot keep is not
// checked; the other checker checks it.

#ifndef WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP
#define WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <optional>
#include <span>
#include <utility>

namespace webcpp::test::constant_time {

namespace crypto = webcpp::crypto;
using crypto::backends::sodium;

/** The bytes of an object, for a checker's primitives. */
template <class T>
std::span<std::uint8_t const> bytes_of(T const& object) {
    return {reinterpret_cast<std::uint8_t const*>(&object), sizeof object};
}

/** Counts a failed check, with its name. */
inline int check(bool ok, char const* what) {
    if (!ok) {
        std::printf("FAILED: %s\n", what);
    }
    return ok ? 0 : 1;
}

/** Whether the checker read its shadow and the secret mark reached `bytes`. */
template <class Checker>
bool carries_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && *traced;
}

/** Whether the checker read its shadow and the secret mark reached none of `bytes`. */
template <class Checker>
bool clear_of_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && !*traced;
}

/** constant_time_equal with both sides secret, its result marked public for the test's branch. */
template <class Checker>
int constant_time_equal_path() {
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    Checker::mark_secret(a);
    Checker::mark_secret(b);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    bool same = crypto::constant_time_equal(a, b);  // NOLINT(misc-const-correctness)
    Checker::mark_public(bytes_of(same));
    return check(same, "constant_time_equal");
}

/**
 * is_all_zero with its bytes secret. The bytes are undefined, not zero, so its result is
 * whatever they hold: only its being traced is checked, where the shadow follows a subtraction's
 * carry (its reduction is ((total - 1) >> 8) & 1).
 */
template <class Checker>
int all_zero() {
    std::array<std::uint8_t, 32> bytes{};
    Checker::mark_secret(bytes);
    bool const zero = crypto::detail::is_all_zero(bytes);
    if constexpr (Checker::exact_subtraction) {
        return check(carries_mark<Checker>(bytes_of(zero)), "is_all_zero");
    } else {
        return 0;
    }
}

/**
 * secret's wipe: a move, a move assignment and the destructor overwrite the bytes they leave
 * behind with constants, without a branch on them, so that the checker holds them public after.
 */
template <class Checker>
int secret_wipe() {
    using secret = crypto::secret<32>;
    alignas(secret) std::array<std::byte, sizeof(secret)> storage{};
    auto* const first = new (storage.data()) secret;
    std::ranges::fill(first->writable(), std::uint8_t{0x42});
    Checker::mark_secret(first->writable());
    secret moved(std::move(*first));
    bool const moved_from_wiped = clear_of_mark<Checker>(first->bytes());
    secret assigned;
    assigned = std::move(moved);
    bool const assigned_from_wiped =
        clear_of_mark<Checker>(moved.bytes());  // NOLINT(bugprone-use-after-move)
    bool const kept = carries_mark<Checker>(assigned.bytes());
    *first = std::move(assigned);
    first->~secret();
    // MemorySanitizer poisons a destroyed object by itself: only a checker that reads it back
    // checks the destructor's wipe.
    bool const destroyed_wiped =
        !Checker::reads_destroyed ||
        clear_of_mark<Checker>(
            {reinterpret_cast<std::uint8_t const*>(storage.data()), storage.size()});
    return check(moved_from_wiped && assigned_from_wiped && kept && destroyed_wiped,
                 "secret's wipe");
}

/**
 * from_key, seal and open of an AEAD or a secret box with the key, the data and the tag secret: an
 * open of the message, then an open of no message under the same tag, which fails. Each verdict
 * must be public: the engine or the library marks it so, and only it.
 */
template <class Checker, class Aead>
int seal_and_open(char const* what) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    Checker::mark_secret(key);
    Checker::mark_secret(data);
    auto made = Aead::from_key(key);
    auto tag = made->seal(iv, {}, data);
    int const failures =
        check(tag.has_value() && carries_mark<Checker>(data) && carries_mark<Checker>(*tag), what);
    Checker::mark_secret(*tag);
    auto const opened = made->open(iv, {}, data, *tag);
    bool const opened_verdict = opened.has_value();
    Checker::verdict(opened_verdict);
    auto const none = made->open(iv, {}, std::span<std::uint8_t>{}, *tag);
    bool const none_verdict = none.has_value();
    Checker::verdict(none_verdict);
    return failures + check(opened_verdict && !none_verdict, what);
}

/** from_key, encrypt and decrypt of ctaes with the key and the block secret. */
template <class Checker>
int ctaes_block() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    key.fill(0x42);
    block.fill(0x17);
    Checker::mark_secret(key);
    Checker::mark_secret(block);
    auto made = crypto::ciphers::aes256<crypto::backends::ctaes>::from_key(key);
    bool const ok = made && made->encrypt(block) && made->decrypt(block);
    return check(ok && carries_mark<Checker>(block), "ctaes");
}

/** Ed25519 on libsodium: from_secret and sign with the seed secret; the kept seed is traced. */
template <class Checker>
int sodium_ed25519() {
    std::array<std::uint8_t, 32> seed{};
    std::array<std::uint8_t, 64> const message{};
    seed.fill(0x42);
    Checker::mark_secret(seed);
    auto const pair = crypto::curves::ed25519::basic_keypair<sodium>::from_secret(seed);
    auto const signature = pair->sign(crypto::eddsa, message);
    auto const kept = pair->secret();
    return check(signature.has_value() && carries_mark<Checker>(*signature),
                 "Ed25519 on libsodium") +
           check(kept.has_value() && carries_mark<Checker>(kept->bytes()),
                 "Ed25519's secret on libsodium");
}

/**
 * X25519 on libsodium: the public key and the agreement with the secret key secret, the peer's
 * public key public. Whether the shared secret is all zero is marked public where webcpp
 * branches on it, in the engine and in `agree`. The public key is checked traced where the
 * shadow follows a subtraction's carry: ref10's table lookup selects public points with masks
 * of the form ((x ^ y) - 1) >> 31.
 */
template <class Checker>
int sodium_x25519() {
    namespace x25519 = crypto::curves::x25519;
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(0x42);
    Checker::mark_secret(secret_key);
    auto const own = x25519::public_key<sodium>(secret_key);
    auto const shared = x25519::agree<sodium>(secret_key, *peer);
    bool const own_traced =
        own.has_value() && (!Checker::exact_subtraction || carries_mark<Checker>(*own));
    return check(own_traced, "X25519's public key on libsodium") +
           check(shared.has_value() && carries_mark<Checker>(shared->bytes()),
                 "X25519's agreement on libsodium");
}

/**
 * A box on libsodium: from_keys with the secret key secret, then seal and open as an AEAD's. The
 * agreement's verdict is libsodium's own branch (sodium_verdicts.supp).
 */
template <class Checker, class Box>
int sodium_box(char const* what) {
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = crypto::curves::x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, Box::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    secret_key.fill(0x42);
    data.fill(0x17);
    Checker::mark_secret(secret_key);
    Checker::mark_secret(data);
    auto made = Box::from_keys(secret_key, *peer);
    auto tag = made->seal(iv, data);
    int const failures =
        check(tag.has_value() && carries_mark<Checker>(data) && carries_mark<Checker>(*tag), what);
    Checker::mark_secret(*tag);
    auto const opened = made->open(iv, data, *tag);
    bool const opened_verdict = opened.has_value();
    Checker::verdict(opened_verdict);
    return failures + check(opened_verdict, what);
}

/**
 * The sealed box on libsodium: seal with the message secret, then open with the recipient's
 * secret key and the sealed box secret. The verdict is libsodium's own branches (the agreement's
 * and the tag's, sodium_verdicts.supp), then the engine's, which marks it public.
 */
template <class Checker>
int sodium_sealed_box() {
    using crypto::public_key_encryption::sealed_box;
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(0x42);
    auto const public_key = crypto::curves::x25519::public_key<sodium>(secret_key);
    std::array<std::uint8_t, 64> message{};
    message.fill(0x17);
    Checker::mark_secret(message);
    std::array<std::uint8_t, 64 + sealed_box::overhead> sealed{};
    bool const sealed_ok =
        public_key.has_value() && sealed_box::seal(*public_key, message, sealed).has_value();
    int const failures = check(sealed_ok && carries_mark<Checker>(sealed), "sealed box's seal");
    Checker::mark_secret(secret_key);
    // The drawn public key, the first 32 bytes, is public: it travels in clear, and libsodium
    // checks its order. The tag and the ciphertext are secret.
    Checker::mark_secret(std::span<std::uint8_t>{sealed}.subspan(32));
    std::array<std::uint8_t, 64> opened{};
    auto const result = sealed_box::open(*public_key, secret_key, sealed, opened);
    bool const opened_verdict = result.has_value();
    Checker::verdict(opened_verdict);
    return failures + check(opened_verdict && carries_mark<Checker>(opened), "sealed box's open");
}

/** kx on libsodium: both key pairs from secret seeds, both sides' session keys. */
template <class Checker>
int sodium_kx() {
    using keypair = crypto::key_exchange::kx_keypair<sodium>;
    std::array<std::uint8_t, 32> client_seed{};
    std::array<std::uint8_t, 32> server_seed{};
    client_seed.fill(0x42);
    server_seed.fill(0x24);
    Checker::mark_secret(client_seed);
    Checker::mark_secret(server_seed);
    auto const client = keypair::derive_from_seed(client_seed);
    auto const server = keypair::derive_from_seed(server_seed);
    auto const client_key = *client->public_key();
    auto const server_key = *server->public_key();
    // The public keys are public: sent to the peer.
    Checker::mark_public(client_key);
    Checker::mark_public(server_key);
    auto const client_keys = client->client_session_keys(server_key);
    auto const server_keys = server->server_session_keys(client_key);
    return check(client_keys.has_value() && server_keys.has_value() &&
                     carries_mark<Checker>(client_keys->receive.bytes()) &&
                     carries_mark<Checker>(server_keys->transmit.bytes()),
                 "kx on libsodium");
}

/** libsecp256k1's key pair, the type every secp256k1 path below makes. */
using secp256k1_pair = crypto::curves::secp256k1::basic_keypair<crypto::backends::secp256k1>;

/** A key pair made from 32 bytes of `value`, its secret key secret, its public key public. */
template <class Checker>
boost::system::result<secp256k1_pair> secp256k1_secret_pair(std::uint8_t value) {
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(value);
    Checker::mark_secret(secret_key);
    return secp256k1_pair::from_secret(secret_key);
}

/** A key pair made from 32 public bytes of `value`: a peer's. */
inline boost::system::result<secp256k1_pair> secp256k1_public_pair(std::uint8_t value) {
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(value);
    return secp256k1_pair::from_secret(secret_key);
}

/**
 * A key pair's public key as its peer reads it: its compressed bytes, marked public since they
 * are sent, made into the peer's `public_key`.
 */
template <class Checker>
boost::system::result<crypto::curves::secp256k1::public_key> secp256k1_sent_key(
    secp256k1_pair const& pair) {
    auto const public_key = pair.public_key();
    std::array<std::uint8_t, 33> sent_key{};
    if (public_key) {
        sent_key = public_key->compressed();
    }
    Checker::mark_public(sent_key);
    return crypto::curves::secp256k1::public_key::from_bytes<crypto::backends::secp256k1>(sent_key);
}

/** The bytes of a caller's workspace, for a checker's primitives. */
template <std::size_t N>
std::span<std::uint8_t const> workspace_bytes(std::array<std::byte, N> const& space) {
    return {reinterpret_cast<std::uint8_t const*>(space.data()), space.size()};
}

/**
 * ECDH on libsecp256k1, its three forms, `agree`, `agree_hashed` and `agree_point`: the key
 * pair's secret secret, the peer's key public. Each shared secret is traced, and so is the
 * secret key `secret()` gives back.
 */
template <class Checker>
int secp256k1_ecdh() {
    auto const pair = secp256k1_secret_pair<Checker>(0x42);
    auto const peer = secp256k1_public_pair(0x24);
    if (!pair || !peer) {
        return check(false, "secp256k1's key pairs for ECDH");
    }
    auto const peer_key = secp256k1_sent_key<Checker>(*peer);
    if (!peer_key) {
        return check(false, "secp256k1's peer key for ECDH");
    }
    auto const x_only = pair->agree(*peer_key);
    auto const hashed = pair->agree_hashed(*peer_key);
    auto const point = pair->agree_point(*peer_key);
    auto const kept = pair->secret();
    return check(x_only.has_value() && carries_mark<Checker>(x_only->bytes()),
                 "secp256k1's agree") +
           check(hashed.has_value() && carries_mark<Checker>(hashed->bytes()),
                 "secp256k1's agree_hashed") +
           check(point.has_value() && carries_mark<Checker>(point->bytes()),
                 "secp256k1's agree_point") +
           check(kept.has_value() && carries_mark<Checker>(kept->bytes()), "secp256k1's secret");
}

/**
 * The key pair's signatures, BIP340 with its auxiliary randomness given and drawn, the
 * recoverable ECDSA and the hedged one of a digest, then its x-only tweak: the key pair's
 * secret, the given auxiliary randomness and the extra entropy secret, the message, the digest
 * and the tweak public (libsecp256k1's `ctime_tests.c` holds the tweak public too). The drawn
 * auxiliary randomness comes from the system's generator, unmarked: its signature is traced
 * through the key pair's secret alone. Each signature is traced.
 */
template <class Checker>
int secp256k1_signing() {
    auto pair = secp256k1_secret_pair<Checker>(0x42);
    if (!pair) {
        return check(false, "secp256k1's key pair for signing");
    }
    std::array<std::uint8_t, 32> message_hash{};
    std::array<std::uint8_t, 32> extra_entropy{};
    message_hash.fill(0x17);
    extra_entropy.fill(0x5a);
    Checker::mark_secret(extra_entropy);
    crypto::prehashed const digest{message_hash};
    auto const schnorr = pair->sign(crypto::schnorr, message_hash, extra_entropy);
    auto const drawn = pair->sign(crypto::schnorr, message_hash);
    auto const recoverable = pair->sign(crypto::ecdsa_sha256_recoverable, digest);
    auto const hedged = pair->sign(crypto::ecdsa_sha256, digest, extra_entropy);
    std::array<std::uint8_t, 32> tweak_bytes{};
    tweak_bytes.fill(0x24);
    auto const tweaked = pair->tweak_xonly(tweak_bytes);
    return check(schnorr.has_value() && carries_mark<Checker>(*schnorr),
                 "secp256k1's sign with schnorr") +
           check(drawn.has_value() && carries_mark<Checker>(*drawn),
                 "secp256k1's sign with schnorr, its auxiliary randomness drawn") +
           check(recoverable.has_value() && carries_mark<Checker>(*recoverable),
                 "secp256k1's sign with ecdsa_sha256_recoverable") +
           check(hedged.has_value() && carries_mark<Checker>(*hedged),
                 "secp256k1's hedged sign with ecdsa_sha256") +
           check(tweaked.has_value(), "secp256k1's tweak_xonly");
}

/** The secret key's tweaks and negation: the secret key and the tweak secret, each result traced.
 */
template <class Checker>
int secp256k1_secret_tweaks() {
    namespace secp256k1 = crypto::curves::secp256k1;
    using backend = crypto::backends::secp256k1;
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, 32> tweak_bytes{};
    secret_key.fill(0x42);
    tweak_bytes.fill(0x17);
    Checker::mark_secret(secret_key);
    Checker::mark_secret(tweak_bytes);
    auto const added = secp256k1::seckey_tweak_add<backend>(secret_key, tweak_bytes);
    auto const multiplied = secp256k1::seckey_tweak_mul<backend>(secret_key, tweak_bytes);
    auto const negated = secp256k1::seckey_negate<backend>(secret_key);
    return check(added.has_value() && carries_mark<Checker>(added->bytes()),
                 "secp256k1's seckey_tweak_add") +
           check(multiplied.has_value() && carries_mark<Checker>(multiplied->bytes()),
                 "secp256k1's seckey_tweak_mul") +
           check(negated.has_value() && carries_mark<Checker>(negated->bytes()),
                 "secp256k1's seckey_negate");
}

/**
 * PKCS#8 on libsecp256k1: the key pair's secret secret, the encoding traced, then the encoding
 * read back with its secret still secret, the decoded key pair's own encoding traced; the
 * re-encoding's comparison is declassified where webcpp branches on it.
 */
template <class Checker>
int secp256k1_pkcs8() {
    namespace secp256k1 = crypto::curves::secp256k1;
    using backend = crypto::backends::secp256k1;
    auto const pair = secp256k1_secret_pair<Checker>(0x42);
    if (!pair) {
        return check(false, "secp256k1's key pair for PKCS#8");
    }
    std::array<std::uint8_t, secp256k1::max_pkcs8_size> encoded{};
    auto const written = secp256k1::encode_pkcs8(*pair, encoded);
    int const failures =
        check(written.has_value() && carries_mark<Checker>(encoded), "secp256k1's encode_pkcs8");
    auto const decoded = secp256k1::decode_pkcs8<backend>(encoded);
    std::array<std::uint8_t, secp256k1::max_pkcs8_size> encoded_again{};
    bool const decoded_traced = decoded.has_value() &&
                                secp256k1::encode_pkcs8(*decoded, encoded_again).has_value() &&
                                carries_mark<Checker>(encoded_again);
    return failures + check(decoded_traced, "secp256k1's decode_pkcs8");
}

/**
 * ElligatorSwift on libsecp256k1: the encoding of a key pair with its secret secret, sent and so
 * public, then the exchange with a peer's encoding, its secret traced. The randomness is public:
 * libsecp256k1 hashes it after it marks the hash of the secret public, since it only chooses
 * among the encodings of the public key (its `secp256k1_ellswift_create`).
 */
template <class Checker>
int secp256k1_ellswift() {
    namespace secp256k1 = crypto::curves::secp256k1;
    auto const pair = secp256k1_secret_pair<Checker>(0x42);
    auto const peer = secp256k1_public_pair(0x24);
    if (!pair || !peer) {
        return check(false, "secp256k1's key pairs for ElligatorSwift");
    }
    std::array<std::uint8_t, 32> randomness{};
    randomness.fill(0x5a);
    auto own_encoding = secp256k1::ellswift_create(*pair, randomness);
    std::array<std::uint8_t, 32> const peer_randomness{};
    auto const peer_encoding = secp256k1::ellswift_create(*peer, peer_randomness);
    if (!own_encoding || !peer_encoding) {
        return check(false, "secp256k1's ellswift_create");
    }
    Checker::mark_public(*own_encoding);
    auto const shared = secp256k1::ellswift_xdh(*pair, *own_encoding, *peer_encoding,
                                                secp256k1::ellswift_party::initiator);
    return check(shared.has_value() && carries_mark<Checker>(shared->bytes()),
                 "secp256k1's ellswift_xdh");
}

/**
 * MuSig2 on libsecp256k1, two signers: one key pair's secret secret, its secret nonce and its
 * partial signature traced; the public keys and the public nonces public, as they are sent.
 */
template <class Checker>
int secp256k1_musig() {
    namespace secp256k1 = crypto::curves::secp256k1;
    namespace musig = secp256k1::musig;
    using backend = crypto::backends::secp256k1;
    auto const pair = secp256k1_secret_pair<Checker>(0x42);
    auto const other = secp256k1_public_pair(0x24);
    if (!pair || !other) {
        return check(false, "secp256k1's key pairs for MuSig2");
    }
    auto const own_key = secp256k1_sent_key<Checker>(*pair);
    auto const other_key = secp256k1_sent_key<Checker>(*other);
    if (!own_key || !other_key) {
        return check(false, "secp256k1's public keys for MuSig2");
    }
    std::array<secp256k1::public_key, 2> keys{*own_key, *other_key};
    std::ranges::sort(keys);
    alignas(std::max_align_t) std::array<std::byte, musig::workspace_size(2)> space{};
    auto const signers_key = musig::key_aggregate<backend>(keys, space);
    std::array<std::uint8_t, 32> message{};
    message.fill(0x17);
    if (!signers_key) {
        return check(false, "secp256k1's key_aggregate");
    }
    auto own_nonce = musig::nonce_gen(*pair, *signers_key, message);
    auto other_nonce = musig::nonce_gen(*other, *signers_key, message);
    if (!own_nonce || !other_nonce) {
        return check(false, "secp256k1's nonce_gen");
    }
    // The secret nonce is made from the secret: traced before it signs.
    int const failures =
        check(carries_mark<Checker>(bytes_of(own_nonce->secret_part)), "secp256k1's nonce_gen");
    Checker::mark_public(bytes_of(own_nonce->public_part));
    std::array<musig::public_nonce, 2> const nonces{
        own_nonce->public_part,
        other_nonce->public_part,
    };
    auto const nonce_sum = musig::nonce_aggregate<backend>(nonces, space);
    if (!nonce_sum) {
        return failures + check(false, "secp256k1's nonce_aggregate");
    }
    auto const signing_session = musig::nonce_process<backend>(*nonce_sum, message, *signers_key);
    if (!signing_session) {
        return failures + check(false, "secp256k1's nonce_process");
    }
    auto const own_part = musig::partial_sign(*pair, std::move(own_nonce->secret_part),
                                              *signers_key, *signing_session);
    if (!own_part) {
        return failures + check(false, "secp256k1's partial_sign");
    }
    auto const part_bytes = musig::serialize_partial_signature<backend>(*own_part);
    return failures + check(carries_mark<Checker>(part_bytes), "secp256k1's partial_sign");
}

/**
 * Silent payments on libsecp256k1: a sender's output from an input whose secret is secret, the
 * workspace that held the input's secret wiped after; a label, its tweak traced, and a
 * recipient's scan with the scan key's secret secret, the scan's workspace wiped after. The
 * public keys, the output and the outpoint are public.
 */
template <class Checker>
int secp256k1_silent_payments() {
    namespace secp256k1 = crypto::curves::secp256k1;
    namespace silent_payments = secp256k1::silent_payments;
    using backend = crypto::backends::secp256k1;
    auto const scan_pair = secp256k1_secret_pair<Checker>(0x51);
    auto const spend_pair = secp256k1_public_pair(0x52);
    auto const input_pair = secp256k1_secret_pair<Checker>(0x53);
    if (!scan_pair || !spend_pair || !input_pair) {
        return check(false, "secp256k1's key pairs for silent payments");
    }
    auto const scan_key = secp256k1_sent_key<Checker>(*scan_pair);
    auto const spend_key = secp256k1_sent_key<Checker>(*spend_pair);
    auto const input_key = secp256k1_sent_key<Checker>(*input_pair);
    if (!scan_key || !spend_key || !input_key) {
        return check(false, "secp256k1's public keys for silent payments");
    }
    silent_payments::recipient const recipient{.scan_key = *scan_key, .spend_key = *spend_key};
    std::array<silent_payments::recipient, 1> const recipients{recipient};
    std::array<std::uint8_t, silent_payments::outpoint_size> outpoint{};
    outpoint.fill(0x01);
    std::array<secp256k1_pair const*, 1> const plain_inputs{&*input_pair};
    std::array<std::array<std::uint8_t, 32>, 1> outputs{};
    alignas(std::max_align_t) std::array<std::byte, silent_payments::send_workspace_size(1, 0, 1)>
        send_space{};
    auto const sent = silent_payments::create_outputs<backend>(recipients, outpoint, {},
                                                               plain_inputs, outputs, send_space);
    int failures = check(sent.has_value() && clear_of_mark<Checker>(workspace_bytes(send_space)),
                         "secp256k1's create_outputs");
    // The output is in the transaction: public.
    Checker::mark_public(outputs[0]);
    auto const made_label = silent_payments::create_label(*scan_pair, 0);
    failures += check(made_label.has_value() && carries_mark<Checker>(made_label->tweak),
                      "secp256k1's create_label");
    std::array<secp256k1::public_key, 1> const input_keys{*input_key};
    alignas(std::max_align_t) std::array<std::byte, silent_payments::summary_workspace_size(0, 1)>
        summary_space{};
    auto const summary =
        silent_payments::make_prevouts_summary<backend>(outpoint, {}, input_keys, summary_space);
    if (!summary) {
        return failures + check(false, "secp256k1's make_prevouts_summary");
    }
    std::array<silent_payments::found_output, 1> found{};
    alignas(std::max_align_t) std::array<std::byte, silent_payments::scan_workspace_size(1)>
        scan_space{};
    auto const found_count =
        silent_payments::scan_outputs(*scan_pair, *spend_key, *summary, outputs, found, scan_space);
    // The found output's tweak is not checked traced: libsecp256k1 marks the hash it is made of
    // public itself, since the scan branches on the output it gives (its silent payments'
    // main_impl.h, "the caller wants to branch when a payment is found").
    return failures +
           check(found_count.has_value() && *found_count == 1, "secp256k1's scan_outputs") +
           check(clear_of_mark<Checker>(workspace_bytes(scan_space)),
                 "secp256k1's scan_outputs, its workspace");
}

/** BearSSL's P-256 key pair, the type every P-256 path below makes. */
using p256_pair = crypto::curves::p256::basic_keypair<crypto::backends::bearssl>;

/** A P-256 key pair made from 32 bytes of `value`, its scalar secret. */
template <class Checker>
boost::system::result<p256_pair> p256_secret_pair(std::uint8_t value) {
    std::array<std::uint8_t, 32> scalar{};
    scalar.fill(value);
    Checker::mark_secret(scalar);
    return p256_pair::from_secret(scalar);
}

/** A P-256 key pair made from 32 public bytes of `value`: a peer's. */
inline boost::system::result<p256_pair> p256_public_pair(std::uint8_t value) {
    std::array<std::uint8_t, 32> scalar{};
    scalar.fill(value);
    return p256_pair::from_secret(scalar);
}

/**
 * P-256's key pair on BearSSL, made with its scalar secret: the range check before BearSSL
 * declassifies its verdict alone, so whether the key pair exists is public and is all the test
 * branches on; the kept scalar is traced, and the public point, d * G, where the shadow follows
 * a subtraction's carry (BearSSL's window lookup selects public points with masks of the form
 * (q | -q) >> 31, which MemorySanitizer counts initialised).
 */
template <class Checker>
int bearssl_p256_make() {
    auto const pair = p256_secret_pair<Checker>(0x42);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    bool made = pair.has_value();  // NOLINT(misc-const-correctness)
    Checker::verdict(made);
    if (!made) {
        return check(false, "P-256's from_secret on BearSSL");
    }
    auto const point = pair->public_key();
    auto const kept = pair->secret();
    bool const point_traced = point.has_value() && (!Checker::exact_subtraction ||
                                                    carries_mark<Checker>(point->uncompressed()));
    return check(point_traced && kept.has_value() && carries_mark<Checker>(kept->bytes()),
                 "P-256's from_secret on BearSSL");
}

/**
 * P-256's ECDSA on BearSSL: a public digest signed with a secret scalar, through the marker,
 * `sign(ecdsa_sha256, prehashed{digest})`, the signature traced (its s is the scalar's multiple)
 * and made low S by `sign` without a branch (`detail::p_curve_high_s_mask`); then made low S and
 * checked low S again as a protocol that requires it does with a signature it has just made.
 * BearSSL's own branches on its verdicts, the scalar's decoding and the nonce's retry, are its
 * function's (bearssl_verdicts.supp); `normalize_low_s` and `is_low_s` branch only on verdicts the
 * library declassifies, a signature being public once it is made (`detail::p_curve_low_s`).
 */
template <class Checker>
int bearssl_p256_sign() {
    namespace p256 = crypto::curves::p256;
    auto const pair = p256_secret_pair<Checker>(0x42);
    if (!pair) {
        return check(false, "P-256's key pair for signing on BearSSL");
    }
    std::array<std::uint8_t, p256::digest_size> digest{};
    digest.fill(0x17);
    auto const signature = pair->sign(crypto::ecdsa_sha256, crypto::prehashed{digest});
    if (!signature) {
        return check(false, "P-256's sign on BearSSL");
    }
    int const failures =
        check(carries_mark<Checker>(*signature), "P-256's sign on BearSSL, traced");
    auto const low = p256::normalize_low_s(*signature);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    // NOLINTNEXTLINE(misc-const-correctness): see above
    bool low_verdict = low.has_value() && p256::is_low_s(*low);
    Checker::verdict(low_verdict);
    return failures + check(low_verdict, "P-256's normalize_low_s and is_low_s");
}

/**
 * P-256's ECDH on BearSSL: the key pair's scalar secret, the peer's public key public. BearSSL's
 * verdict, which folds in its check of the scalar, is declassified in the engine. The shared x is
 * traced where the shadow follows a subtraction's carry: BearSSL selects the window's public
 * multiples of the peer's point with masks of the form (q | -q) >> 31.
 */
template <class Checker>
int bearssl_p256_ecdh() {
    auto const pair = p256_secret_pair<Checker>(0x42);
    auto const peer = p256_public_pair(0x24);
    if (!pair || !peer) {
        return check(false, "P-256's key pairs for ECDH on BearSSL");
    }
    auto const peer_key = peer->public_key();
    if (!peer_key) {
        return check(false, "P-256's peer key on BearSSL");
    }
    auto const shared = pair->agree(*peer_key);
    return check(shared.has_value() &&
                     (!Checker::exact_subtraction || carries_mark<Checker>(shared->bytes())),
                 "P-256's agree on BearSSL");
}

/**
 * P-256's PKCS#8 on BearSSL: a peer's encoding, public, whose scalar's bytes are then marked
 * secret, decoded; the range check's verdict and the re-encoding's comparison of the public
 * point are declassified where the library branches on them, and the decoded key pair's scalar
 * is traced.
 */
template <class Checker>
int bearssl_p256_pkcs8() {
    namespace p256 = crypto::curves::p256;
    auto const pair = p256_public_pair(0x42);
    if (!pair) {
        return check(false, "P-256's key pair for PKCS#8 on BearSSL");
    }
    std::array<std::uint8_t, p256::max_pkcs8_size> encoded{};
    if (!p256::encode_pkcs8(*pair, encoded)) {
        return check(false, "P-256's encode_pkcs8 on BearSSL");
    }
    Checker::mark_secret(std::span<std::uint8_t>(encoded).subspan(
        crypto::detail::p256_pkcs8_prefix.size(), p256::secret_key_size));
    auto const decoded = p256::decode_pkcs8<crypto::backends::bearssl>(encoded);
    if (!decoded) {
        return check(false, "P-256's decode_pkcs8 on BearSSL");
    }
    auto const kept = decoded->secret();
    return check(kept.has_value() && carries_mark<Checker>(kept->bytes()),
                 "P-256's decode_pkcs8 on BearSSL");
}

/** Every P-256 path above, on the checker: the number of failed checks. */
template <class Checker>
int bearssl_p256_paths() {
    return bearssl_p256_make<Checker>() + bearssl_p256_sign<Checker>() +
           bearssl_p256_ecdh<Checker>() + bearssl_p256_pkcs8<Checker>();
}

#ifdef WEBCPP_TEST_CRYPTO_PLANTED_SCALAR_CHECK
/**
 * The planted leak of the P-256 paths: `detail::p_curve_scalar_valid` copied with an early return
 * on the first byte where the scalar and the bound differ, a branch on a secret byte that each
 * checker must report. Compiled only into the planted programs, ctgrind_planted_scalar and
 * msan_planted_scalar, which run it before every path and whose drivers require the report to
 * name it.
 *
 * @param value The secret scalar.
 * @param bound The group order.
 * @return Whether 0 < value < bound.
 */
template <std::size_t N>
bool planted_scalar_valid(std::span<std::uint8_t const, N> value,
                          std::array<std::uint8_t, N> const& bound) {
    unsigned nonzero = 0;
    for (std::uint8_t const byte : value) {
        nonzero |= byte;
    }
    for (std::size_t i = 0; i < N; ++i) {
        if (value[i] != bound[i]) {  // the planted leak: an early exit on a secret byte
            return nonzero != 0 && value[i] < bound[i];
        }
    }
    return false;
}

/** The planted scalar check, run on a secret scalar: the checker must report its branch. */
template <class Checker>
int planted_scalar_check() {
    std::array<std::uint8_t, 32> scalar{};
    scalar.fill(0x42);
    Checker::mark_secret(scalar);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    bool valid = planted_scalar_valid(  // NOLINT(misc-const-correctness)
        std::span<std::uint8_t const, 32>(scalar),
        crypto::detail::p_curve_traits<crypto::families::p256>::order);
    Checker::mark_public(bytes_of(valid));
    return check(valid, "the planted scalar check");
}
#endif

/** Every secp256k1 path above, on the checker: the number of failed checks. */
template <class Checker>
int secp256k1_paths() {
    return secp256k1_ecdh<Checker>() + secp256k1_signing<Checker>() +
           secp256k1_secret_tweaks<Checker>() + secp256k1_pkcs8<Checker>() +
           secp256k1_ellswift<Checker>() + secp256k1_musig<Checker>() +
           secp256k1_silent_payments<Checker>();
}

/** Every path above, on the checker: the number of failed checks. */
template <class Checker>
int common_paths() {
    namespace ciphers = crypto::ciphers;
    return constant_time_equal_path<Checker>() + all_zero<Checker>() + secret_wipe<Checker>() +
           ctaes_block<Checker>() +
           seal_and_open<Checker, ciphers::chacha20_poly1305<crypto::backends::bearssl>>(
               "BearSSL ChaCha") +
           sodium_ed25519<Checker>() + sodium_x25519<Checker>() +
           seal_and_open<Checker, ciphers::chacha20_poly1305<sodium>>(
               "ChaCha20-Poly1305 on libsodium") +
           seal_and_open<Checker, ciphers::chacha20_poly1305_original<sodium>>(
               "the original on libsodium") +
           seal_and_open<Checker, ciphers::xchacha20_poly1305<sodium>>(
               "XChaCha20-Poly1305 on libsodium") +
           seal_and_open<Checker, ciphers::secretbox<sodium>>("secretbox on libsodium") +
           seal_and_open<Checker, ciphers::secretbox_xchacha20poly1305<sodium>>(
               "its XChaCha20 twin") +
           sodium_box<Checker, crypto::public_key_encryption::basic_box<
                                   crypto::families::box_xsalsa20poly1305, sodium>>(
               "box on libsodium") +
           sodium_box<Checker, crypto::public_key_encryption::basic_box<
                                   crypto::families::box_xchacha20poly1305, sodium>>(
               "box_xchacha20poly1305 on libsodium") +
           sodium_sealed_box<Checker>() + sodium_kx<Checker>() + secp256k1_paths<Checker>() +
           bearssl_p256_paths<Checker>();
}

}  // namespace webcpp::test::constant_time

#endif  // WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP
