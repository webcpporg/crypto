// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// public_key_encryption::box, crypto_box, and public_key_encryption::sealed_box, crypto_box_seal,
// on libsodium, their default on every target.
//
// The box: NaCl's case of libsodium's test/default/box.c and box2.c, Alice's secret key with
// Bob's public key and Bob's with Alice's, which box.exp and box2.exp show give one ciphertext
// and tag; the same keys, nonce and message under XChaCha20-Poly1305
// (crypto_box_curve25519xchacha20poly1305), whose ciphertext and tag libsodium's tests do not
// print and which an independent implementation of X25519, HChaCha20, ChaCha20 and Poly1305
// computed (checked against libsodium's own XChaCha20 secret boxes and RFC 7748), the script
// box_xchacha20poly1305_vector.py beside this file, which prints them; every check
// of support/aead_checks.hpp that applies to an object with no additional data, made of an
// X25519 key pair and a peer's X25519 public key (ruling C35); two parties' boxes, each from its
// own key pair and the other's public key, opening each other's messages; a failed open
// (a changed byte: authentication_failed, the data zeroed; a 12-byte nonce: invalid_nonce_size,
// the data untouched); the guards of from_keys (a moved-from key pair: invalid_state); a peer
// key of small order refused with weak_public_key, as libsodium's beforenm refuses it; and the
// box as the secret box under its precomputed key; the box form secret_key_encryption::seal(box,
// nonce, data) and open giving the member's results, and no seal of a box that takes associated
// data.
//
// The sealed box, on the same typed keys: libsodium's test/default/box_seal.c, a message sealed
// to a public key and opened by its recipient's key pair, sealed in place, refused
// (authentication_failed, the output zeroed) with another key pair, after any byte of it changes
// and one byte shorter; two seals of one message differ; the sizes checked first, then the key
// pair (a moved-from one: invalid_state).

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>
#include <webcpp/crypto/secret_key_encryption/authenticated_box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <sodium/crypto_box.h>  // its MESSAGEBYTES_MAX

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace public_key_encryption = webcpp::crypto::public_key_encryption;
namespace x25519 = webcpp::crypto::curves::x25519;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace {

using public_key_encryption::box;
using box_xchacha = public_key_encryption::box_xchacha20poly1305;
using public_key_encryption::sealed_box;

static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::box_xsalsa20poly1305>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::box_xchacha20poly1305>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::sealed_box>,
                             crypto::backends::sodium>);
static_assert(
    std::is_same_v<box, public_key_encryption::basic_box<crypto::families::box_xsalsa20poly1305,
                                                         crypto::backends::sodium>>);
static_assert(std::is_same_v<
              box_xchacha, public_key_encryption::basic_box<crypto::families::box_xchacha20poly1305,
                                                            crypto::backends::sodium>>);
static_assert(
    std::is_same_v<sealed_box, public_key_encryption::basic_sealed_box<crypto::backends::sodium>>);
static_assert(std::is_same_v<box::family_type, crypto::families::box_xsalsa20poly1305>);
static_assert(std::is_same_v<box::name_type, crypto::families::box_xsalsa20poly1305>);
static_assert(std::is_same_v<sealed_box::family_type, crypto::families::sealed_box>);
static_assert(std::is_same_v<sealed_box::name_type, crypto::families::sealed_box>);
static_assert(crypto::supports_v<box, crypto::backends::sodium>);
static_assert(crypto::supports_v<box_xchacha, crypto::backends::sodium>);
static_assert(crypto::supports_v<sealed_box, crypto::backends::sodium>);
static_assert(box::key_size == 32 && box::nonce_size == 24 && box::tag_size == 16);
static_assert(box_xchacha::key_size == 32 && box_xchacha::nonce_size == 24 &&
              box_xchacha::tag_size == 16);
static_assert(sealed_box::overhead == 48);
// The longest message is libsodium's on a 64-bit target; on a 32-bit one libsodium's is the
// smaller, 2^32 - 17, as the Doc Comment says.
static_assert(box::max_message_size == ~std::uint64_t{0} - 16 &&
              box_xchacha::max_message_size == box::max_message_size);
// NOLINTBEGIN(bugprone-branch-clone): libsodium's limit is its SODIUM_MIN macro, a ?: whose two
// operands are the same value on 64-bit Linux.
static_assert(sizeof(std::size_t) != 8 || box::max_message_size == crypto_box_MESSAGEBYTES_MAX);
static_assert(sizeof(std::size_t) == 8 || crypto_box_MESSAGEBYTES_MAX == 0xffffffffU - 16);
// NOLINTEND(bugprone-branch-clone)
// Move-only: the precomputed key has one owner, which wipes it.
static_assert(!std::is_copy_constructible_v<box> && !std::is_copy_assignable_v<box>);
static_assert(std::is_nothrow_move_constructible_v<box> && std::is_nothrow_move_assignable_v<box>);

/**
 * NaCl's keys and nonce (libsodium's test/default/box.c and box2.c): Alice's secret key and
 * Bob's public key; the cases below hold Bob's secret key and Alice's public key too.
 */
constexpr std::string_view alice_secret =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view bob_public =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
constexpr std::string_view nacl_nonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
/** box.c's message after its 32 zero bytes, which box2.exp prints opened. */
constexpr std::string_view nacl_message =
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e"
    "6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a"
    "838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705";
/** A public key of small order, box.c's small_order_p. */
constexpr std::string_view small_order =
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800";

/**
 * NaCl's box, Alice to Bob (box.exp: the tag, then the ciphertext) and Bob opening it with his
 * secret key and Alice's public key (box2.exp). An aead_case's key is the secret key followed
 * by the peer's public key.
 */
constexpr std::array<webcpp::test::aead_case, 2> box_cases{
    webcpp::test::aead_case{
        .key = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
               "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        .nonce = nacl_nonce,
        .associated_data = "",
        .plaintext = nacl_message,
        .ciphertext =
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7"
            "f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368"
            "517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb4"
            "5a74e355a5",
        .tag = "f3ffc7703f9400e52a7dfb4b3d3305d9",
    },
    webcpp::test::aead_case{
        .key = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
               "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        .nonce = nacl_nonce,
        .associated_data = "",
        .plaintext = nacl_message,
        .ciphertext =
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7"
            "f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368"
            "517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb4"
            "5a74e355a5",
        .tag = "f3ffc7703f9400e52a7dfb4b3d3305d9",
    },
};

/**
 * The same keys, nonce and message in crypto_box_curve25519xchacha20poly1305, both ways: the
 * ciphertext and tag box_xchacha20poly1305_vector.py prints. Its precomputed key, HChaCha20 of
 * the X25519 shared secret under a zero nonce, is box_xchacha_key.
 */
constexpr std::array<webcpp::test::aead_case, 2> box_xchacha_cases{
    webcpp::test::aead_case{
        .key = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
               "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        .nonce = nacl_nonce,
        .associated_data = "",
        .plaintext = nacl_message,
        .ciphertext =
            "ef2c6061b7bcec0cfd723055f61f1ccca2946d5a04dbf83151f4894223ac9bc790c660e19dc64cc0d7f9"
            "c7689ad1909955e7a9a7bdac777d6a7967d000ce841fc0f8f31d6d8720b374bc28982764a7dbeb4daa97"
            "7aae1b7350fac79a177ece7541fed264461ea93e6d7ad9fc08c91e774abe79036e7f79ddcc6aab3abf52"
            "7631048ce1",
        .tag = "0b4ff00742f3c1aa99a6321e3883b03c",
    },
    webcpp::test::aead_case{
        .key = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
               "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        .nonce = nacl_nonce,
        .associated_data = "",
        .plaintext = nacl_message,
        .ciphertext =
            "ef2c6061b7bcec0cfd723055f61f1ccca2946d5a04dbf83151f4894223ac9bc790c660e19dc64cc0d7f9"
            "c7689ad1909955e7a9a7bdac777d6a7967d000ce841fc0f8f31d6d8720b374bc28982764a7dbeb4daa97"
            "7aae1b7350fac79a177ece7541fed264461ea93e6d7ad9fc08c91e774abe79036e7f79ddcc6aab3abf52"
            "7631048ce1",
        .tag = "0b4ff00742f3c1aa99a6321e3883b03c",
    },
};

/** NaCl's precomputed key of Alice and Bob, secretbox.c's "firstkey". */
constexpr std::string_view box_key =
    "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
/** Their precomputed key in crypto_box_curve25519xchacha20poly1305. */
constexpr std::string_view box_xchacha_key =
    "8e47ca376bdc7e59d2ced8107ceb2c27f4a80e8575f996baffb1a869ffcd5179";

/**
 * How the checks of support/aead_checks.hpp reach a box: its "key" is the secret key of the own
 * X25519 key pair followed by the peer's X25519 public key, 64 bytes, each made into its typed
 * key before from_keys, and it has no additional data, which its calls do not take (the checks
 * pass none).
 */
template <class Box>
struct box_calls {
    using object = Box;
    static constexpr std::size_t key_size = 64;
    static constexpr std::size_t nonce_size = Box::nonce_size;
    static constexpr std::size_t tag_size = Box::tag_size;
    static constexpr bool has_additional_data = false;
    static constexpr bool one_key = false;

    static boost::system::result<Box> from_key(std::span<std::uint8_t const> key) {
        auto const split = std::min<std::size_t>(key.size(), 32);
        auto const own =
            x25519::basic_keypair<typename Box::backend_type>::from_secret(key.first(split));
        if (!own) {
            return own.error();
        }
        auto const peer = x25519::public_key::from_bytes(key.subspan(split));
        if (!peer) {
            return peer.error();
        }
        return Box::from_keys(*own, *peer);
    }

    static auto seal(Box& made, std::span<std::uint8_t const> nonce,
                     std::span<std::uint8_t const> associated_data, std::span<std::uint8_t> data) {
        BOOST_TEST(associated_data.empty());
        return made.seal(nonce, data);
    }

    static auto open(Box& made, std::span<std::uint8_t const> nonce,
                     std::span<std::uint8_t const> associated_data, std::span<std::uint8_t> data,
                     std::span<std::uint8_t const> tag) {
        BOOST_TEST(associated_data.empty());
        return made.open(nonce, data, tag);
    }
};

/** Alice's key pair, NaCl's (box.c's alicesk). */
x25519::keypair alice_keypair() {
    return x25519::keypair::from_secret(from_hex(alice_secret)).value();
}

/** Bob's public key, NaCl's (box.c's bobpk). */
x25519::public_key bob_public_key() {
    return x25519::public_key::from_bytes(from_hex(bob_public)).value();
}

/**
 * from_keys' guards: a moved-from key pair (invalid_state); a peer key of small order, as
 * libsodium's beforenm refuses it (weak_public_key), and the all-zero point. The keys' sizes are
 * their types': a byte form is not taken.
 */
template <class Box>
void check_box_from_keys() {
    auto own = alice_keypair();
    auto const peer = bob_public_key();
    BOOST_TEST(Box::from_keys(own, x25519::public_key::from_bytes(from_hex(small_order)).value())
                   .error() == crypto::error::weak_public_key);
    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(Box::from_keys(own, x25519::public_key::from_bytes(zero).value()).error() ==
               crypto::error::weak_public_key);
    BOOST_TEST(Box::from_keys(own, peer).has_value());
    x25519::keypair const kept = std::move(own);
    BOOST_TEST(Box::from_keys(kept, peer).has_value());
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from pair
    BOOST_TEST(Box::from_keys(own, peer).error() == crypto::error::invalid_state);
}

/** Whether a box is made from keys of types Own and Peer. */
template <class Box, class Own, class Peer>
concept made_from = requires(Own const& own, Peer const& peer) { Box::from_keys(own, peer); };

// A box takes the typed keys: the byte form is gone (design D3).
static_assert(made_from<box, x25519::keypair, x25519::public_key>);
static_assert(!made_from<box, std::array<std::uint8_t, 32>, std::array<std::uint8_t, 32>>);
static_assert(!made_from<box, std::span<std::uint8_t const>, std::span<std::uint8_t const>>);
static_assert(!made_from<box, x25519::keypair, std::array<std::uint8_t, 32>>);

/**
 * Two parties, each with a drawn key pair: each one's box, from its own key pair and the other's
 * public key, opens what the other's seals, both ways.
 */
template <class Box>
void check_two_parties() {
    auto const alice = x25519::keypair::generate();
    auto const bob = x25519::keypair::generate();
    if (!BOOST_TEST(alice.has_value()) || !BOOST_TEST(bob.has_value())) {
        return;
    }
    auto alice_box = Box::from_keys(*alice, *bob->public_key());
    auto bob_box = Box::from_keys(*bob, *alice->public_key());
    if (!BOOST_TEST(alice_box.has_value()) || !BOOST_TEST(bob_box.has_value())) {
        return;
    }
    std::array<std::uint8_t, Box::nonce_size> nonce{};
    nonce.fill(0x31);
    auto const plain = from_hex(nacl_message);
    auto data = plain;
    auto const tag = alice_box->seal(nonce, data);
    BOOST_TEST(tag.has_value() && data != plain);
    BOOST_TEST(tag.has_value() && bob_box->open(nonce, data, *tag).has_value() && data == plain);
    nonce.fill(0x32);
    auto const reply_tag = bob_box->seal(nonce, data);
    BOOST_TEST(reply_tag.has_value() && data != plain);
    BOOST_TEST(reply_tag.has_value() && alice_box->open(nonce, data, *reply_tag).has_value() &&
               data == plain);
}

/**
 * A failed open (Review Focus 3): one flipped byte gives authentication_failed with the data
 * zeroed; a 12-byte nonce gives invalid_nonce_size with the data untouched.
 */
template <class Box>
void check_open_failures() {
    auto const own = alice_keypair();
    auto made = Box::from_keys(own, bob_public_key());
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const nonce = from_hex(nacl_nonce);
    auto data = from_hex(nacl_message);
    auto const tag = made->seal(nonce, data);
    if (!BOOST_TEST(tag.has_value())) {
        return;
    }
    auto flipped = data;
    flipped[7] ^= 0x01U;
    BOOST_TEST(made->open(nonce, flipped, *tag).error() == crypto::error::authentication_failed);
    BOOST_TEST(webcpp::test::all_zero(flipped));
    auto untouched = data;
    BOOST_TEST(made->open(std::span(nonce).first(12), untouched, *tag).error() ==
               crypto::error::invalid_nonce_size);
    BOOST_TEST(untouched == data);
}

/**
 * A box is the secret box of the same construction under its precomputed key: libsodium's
 * crypto_box_afternm is crypto_secretbox, and its XChaCha20 twin the XChaCha20 secret box.
 */
template <class Box, class Secretbox>
void check_box_is_secretbox(std::string_view key) {
    auto made_box = Box::from_keys(alice_keypair(), bob_public_key());
    auto made_secretbox = Secretbox::from_key(from_hex(key));
    if (!BOOST_TEST(made_box.has_value()) || !BOOST_TEST(made_secretbox.has_value())) {
        return;
    }
    auto const nonce = from_hex(nacl_nonce);
    auto by_box = from_hex(nacl_message);
    auto by_secretbox = by_box;
    auto const box_tag = made_box->seal(nonce, by_box);
    auto const secretbox_tag = made_secretbox->seal(nonce, by_secretbox);
    BOOST_TEST(box_tag && secretbox_tag && to_hex(*box_tag) == to_hex(*secretbox_tag));
    BOOST_TEST(by_box == by_secretbox);
}

/**
 * The box form, `secret_key_encryption::seal(box, nonce, data)` and `open`, named in full, gives
 * the member's ciphertext and tag and opens them, as for a secret box (design R21).
 */
template <class Box>
void check_box_forms() {
    auto made_box = Box::from_keys(alice_keypair(), bob_public_key());
    if (!BOOST_TEST(made_box.has_value())) {
        return;
    }
    auto const nonce = from_hex(nacl_nonce);
    auto const message = from_hex(nacl_message);
    auto by_member = message;
    auto by_free = message;
    auto const member_tag = made_box->seal(nonce, by_member);
    auto const free_tag = crypto::secret_key_encryption::seal(*made_box, nonce, by_free);
    static_assert(std::is_same_v<decltype(free_tag), decltype(member_tag)>);
    if (!BOOST_TEST(member_tag.has_value()) || !BOOST_TEST(free_tag.has_value())) {
        return;
    }
    BOOST_TEST_EQ(to_hex(*free_tag), to_hex(*member_tag));
    BOOST_TEST(by_free == by_member);
    auto const tag = std::span<std::uint8_t const>(free_tag->data(), free_tag->size());
    BOOST_TEST(crypto::secret_key_encryption::open(*made_box, nonce, by_free, tag).has_value());
    BOOST_TEST(by_free == message);
    auto changed_tag = *free_tag;
    changed_tag.data()[0] ^= 0x01U;
    BOOST_TEST(crypto::secret_key_encryption::open(
                   *made_box, nonce, by_member,
                   std::span<std::uint8_t const>(changed_tag.data(), changed_tag.size()))
                   .error() == crypto::error::authentication_failed);
    BOOST_TEST(std::ranges::all_of(by_member, [](std::uint8_t byte) { return byte == 0; }));
}

/** Whether a box seals with associated data, as an AEAD does: none does. */
template <class Box>
concept box_seals_with_associated_data = requires(
    Box& keyed, std::span<std::uint8_t const> nonce_bytes,
    std::span<std::uint8_t const> associated_data_bytes, std::span<std::uint8_t> data_bytes) {
    keyed.seal(nonce_bytes, associated_data_bytes, data_bytes);
};

static_assert(crypto::secret_key_encryption::authenticated_box<box> &&
              crypto::secret_key_encryption::authenticated_box<box_xchacha>);
static_assert(!box_seals_with_associated_data<box> && !box_seals_with_associated_data<box_xchacha>);

/** A recipient's key pair, its secret key's bytes all `fill`, and its X25519 public key. */
struct recipient {
    x25519::keypair key_pair;
    x25519::public_key public_key;

    explicit recipient(std::uint8_t fill)
        : key_pair(made_keypair(fill)), public_key(key_pair.public_key().value()) {}

private:
    static x25519::keypair made_keypair(std::uint8_t fill) {
        std::array<std::uint8_t, 32> secret_key{};
        secret_key.fill(fill);
        return x25519::keypair::from_secret(secret_key).value();
    }
};

/** A message of `size` bytes counting up from 3. */
std::vector<std::uint8_t> sealed_message(std::size_t size) {
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<std::uint8_t>((i * 5) + 3);
    }
    return bytes;
}

/**
 * An open that fails with authentication_failed and zeroes its output, filled beforehand with
 * a pattern that is not zero.
 */
void expect_sealed_refused(x25519::keypair const& key_pair, std::span<std::uint8_t const> sealed) {
    std::vector<std::uint8_t> out(sealed.size() - sealed_box::overhead, 0x77);
    BOOST_TEST(sealed_box::open(key_pair, sealed, out).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(webcpp::test::all_zero(out));
}

/**
 * libsodium's tv1: a message sealed to a public key opens with the recipient's key pair alone;
 * another key pair, any byte changed and a sealed box one byte shorter are refused, the output
 * zeroed; two seals of one message differ, each carrying its own ephemeral public key first.
 */
void check_sealed_box() {
    recipient const bob(0x11);
    recipient const eve(0x22);
    auto const plain = sealed_message(100);
    std::vector<std::uint8_t> sealed(plain.size() + sealed_box::overhead);
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, sealed).has_value());
    BOOST_TEST(
        !std::equal(bob.public_key.bytes().begin(), bob.public_key.bytes().end(), sealed.begin()));
    std::vector<std::uint8_t> opened(plain.size());
    BOOST_TEST(sealed_box::open(bob.key_pair, sealed, opened).has_value());
    BOOST_TEST(opened == plain);
    // Another seal of the same message, under another ephemeral key pair.
    std::vector<std::uint8_t> again(sealed.size());
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, again).has_value());
    BOOST_TEST(again != sealed);
    BOOST_TEST(!std::equal(again.begin(), again.begin() + 32, sealed.begin()));
    // Another key pair, Eve's.
    expect_sealed_refused(eve.key_pair, sealed);
    // Any byte changed: the ephemeral public key, the tag or the ciphertext.
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        auto changed = sealed;
        changed[i] ^= 0x40U;
        expect_sealed_refused(bob.key_pair, changed);
    }
    // One byte shorter.
    expect_sealed_refused(bob.key_pair, std::span(sealed).first(sealed.size() - 1));
    // The refusals end nothing: the sealed box still opens.
    BOOST_TEST(sealed_box::open(bob.key_pair, sealed, opened).has_value());
    BOOST_TEST(opened == plain);
}

/**
 * libsodium's tv2: a message sealed in place, at the start of the output, opens. An empty
 * message seals into the overhead alone and opens into an empty span.
 */
void check_sealed_box_edges() {
    recipient const bob(0x33);
    auto const plain = sealed_message(57);
    std::vector<std::uint8_t> buffer(plain.size() + sealed_box::overhead);
    std::ranges::copy(plain, buffer.begin());
    BOOST_TEST(sealed_box::seal(bob.public_key, std::span(buffer).first(plain.size()), buffer)
                   .has_value());
    std::vector<std::uint8_t> opened(plain.size());
    BOOST_TEST(sealed_box::open(bob.key_pair, buffer, opened).has_value());
    BOOST_TEST(opened == plain);
    std::array<std::uint8_t, sealed_box::overhead> empty_sealed{};
    BOOST_TEST(sealed_box::seal(bob.public_key, {}, empty_sealed).has_value());
    BOOST_TEST(sealed_box::open(bob.key_pair, empty_sealed, std::span<std::uint8_t>()).has_value());
    empty_sealed[40] ^= 1U;
    BOOST_TEST(sealed_box::open(bob.key_pair, empty_sealed, std::span<std::uint8_t>()).error() ==
               crypto::error::authentication_failed);
}

/**
 * The guards, in their order: the sizes first (invalid_input_size: an output not of the
 * message's size plus the overhead, a sealed box shorter than the overhead, an output not of
 * its size less the overhead), then the key pair (invalid_state, moved from); each refusal leaves
 * the output untouched. A recipient key of small order is refused when sealing
 * (weak_public_key), the output zeroed. The keys' sizes are their types'.
 */
void check_sealed_box_guards() {
    recipient bob(0x44);
    auto const plain = sealed_message(10);
    std::vector<std::uint8_t> out(plain.size() + sealed_box::overhead, 0x55);
    for (std::size_t const size :
         {std::size_t{0}, std::size_t{47}, plain.size() + 47, plain.size() + 49}) {
        std::vector<std::uint8_t> wrong(size, 0x55);
        auto const wrong_untouched = wrong;
        BOOST_TEST(sealed_box::seal(bob.public_key, plain, wrong).error() ==
                   crypto::error::invalid_input_size);
        BOOST_TEST(wrong == wrong_untouched);
    }
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, out).has_value());
    auto const sealed = out;
    std::vector<std::uint8_t> opened(plain.size(), 0x66);
    auto const opened_untouched = opened;
    // A sealed box shorter than the overhead, and outputs of other sizes than it holds.
    for (std::size_t const size : {std::size_t{0}, std::size_t{47}}) {
        std::vector<std::uint8_t> const too_short(size, 1);
        BOOST_TEST(sealed_box::open(bob.key_pair, too_short, std::span<std::uint8_t>()).error() ==
                   crypto::error::invalid_input_size);
    }
    x25519::keypair const kept = std::move(bob.key_pair);
    for (std::size_t const size : {std::size_t{0}, plain.size() - 1, plain.size() + 1}) {
        std::vector<std::uint8_t> wrong(size, 0x66);
        BOOST_TEST(sealed_box::open(kept, sealed, wrong).error() ==
                   crypto::error::invalid_input_size);
        // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): moved from
        BOOST_TEST(sealed_box::open(bob.key_pair, sealed, wrong).error() ==
                   crypto::error::invalid_input_size);
    }
    // A moved-from key pair holds no key: invalid_state, the output untouched.
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): moved from
    BOOST_TEST(sealed_box::open(bob.key_pair, sealed, opened).error() ==
               crypto::error::invalid_state);
    BOOST_TEST(opened == opened_untouched);
    BOOST_TEST(sealed_box::open(kept, sealed, opened).has_value() && opened == plain);
    // A recipient key of small order: libsodium's box refuses it, and the output is zeroed.
    BOOST_TEST(
        sealed_box::seal(x25519::public_key::from_bytes(from_hex(small_order)).value(), plain, out)
            .error() == crypto::error::weak_public_key);
    BOOST_TEST(webcpp::test::all_zero(out));
}

/** Whether the sealed box seals to a key of type Key and opens with one of type Pair. */
template <class Key>
concept seals_to = requires(Key const& key, std::span<std::uint8_t> out) {
    sealed_box::seal(key, std::span<std::uint8_t const>{}, out);
};
template <class Pair>
concept opens_with = requires(Pair const& pair, std::span<std::uint8_t> out) {
    sealed_box::open(pair, std::span<std::uint8_t const>{}, out);
};
/** Whether the sealed box opens with a public key and a secret key, both of type Key. */
template <class Key>
concept opens_with_two_keys = requires(Key const& key, std::span<std::uint8_t> out) {
    sealed_box::open(key, key, std::span<std::uint8_t const>{}, out);
};

// The sealed box takes the typed keys: the byte forms are gone (design D3).
static_assert(seals_to<x25519::public_key>);
static_assert(!seals_to<std::array<std::uint8_t, 32>>);
static_assert(!seals_to<std::span<std::uint8_t const>>);
static_assert(opens_with<x25519::keypair>);
static_assert(!opens_with<std::array<std::uint8_t, 32>>);
static_assert(!opens_with_two_keys<std::span<std::uint8_t const>>);

}  // namespace

int main() {
    webcpp::test::check_aead_with<box_calls<box>>(box_cases);
    webcpp::test::check_aead_with<box_calls<box_xchacha>>(box_xchacha_cases);
    check_box_from_keys<box>();
    check_box_from_keys<box_xchacha>();
    check_two_parties<box>();
    check_two_parties<box_xchacha>();
    check_open_failures<box>();
    check_open_failures<box_xchacha>();
    check_box_is_secretbox<box, crypto::secret_key_encryption::secretbox<>>(box_key);
    check_box_is_secretbox<box_xchacha,
                           crypto::secret_key_encryption::secretbox_xchacha20poly1305<>>(
        box_xchacha_key);
    check_box_forms<box>();
    check_box_forms<box_xchacha>();
    check_sealed_box();
    check_sealed_box_edges();
    check_sealed_box_guards();
    return webcpp::test::exit_status(boost::report_errors());
}
