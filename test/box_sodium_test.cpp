// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// hybrid::box, crypto_box, and hybrid::sealed_box, crypto_box_seal, on libsodium, their default
// on every target.
//
// The box: NaCl's case of libsodium's test/default/box.c and box2.c, Alice's secret key with
// Bob's public key and Bob's with Alice's, which box.exp and box2.exp show give one ciphertext
// and tag; the same keys, nonce and message under XChaCha20-Poly1305
// (crypto_box_curve25519xchacha20poly1305), whose ciphertext and tag libsodium's tests do not
// print and which an independent implementation of X25519, HChaCha20, ChaCha20 and Poly1305
// computed (checked against libsodium's own XChaCha20 secret boxes and RFC 7748), the script
// box_xchacha20poly1305_vector.py beside this file, which prints them; every check
// of support/aead_checks.hpp that applies to an object with no additional data, made of a
// secret key and a peer's public key (ruling C35); the guards of from_keys; a peer key of small
// order refused with weak_public_key, as libsodium's beforenm refuses it; and the box as the
// secret box under its precomputed key.
//
// The sealed box: libsodium's test/default/box_seal.c, a message sealed to a public key and
// opened by its recipient, sealed in place, refused (authentication_failed, the output zeroed)
// with another key pair, with the keys swapped, after any byte of it changes and one byte
// shorter; two seals of one message differ; the sizes checked first, then the keys.

#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <sodium/crypto_box.h>  // its MESSAGEBYTES_MAX

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace crypto = webcpp::crypto;
namespace hybrid = webcpp::crypto::hybrid;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace {

using hybrid::box;
using box_xchacha = hybrid::box_xchacha20poly1305;
using hybrid::sealed_box;

static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::box_xsalsa20poly1305>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::box_xchacha20poly1305>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<crypto::default_backend_t<crypto::families::sealed_box>,
                             crypto::backends::sodium>);
static_assert(std::is_same_v<box, hybrid::basic_box<crypto::families::box_xsalsa20poly1305,
                                                    crypto::backends::sodium>>);
static_assert(std::is_same_v<box_xchacha, hybrid::basic_box<crypto::families::box_xchacha20poly1305,
                                                            crypto::backends::sodium>>);
static_assert(std::is_same_v<sealed_box, hybrid::basic_sealed_box<crypto::backends::sodium>>);
static_assert(std::is_same_v<box::family_type, crypto::families::box_xsalsa20poly1305>);
static_assert(std::is_same_v<box::name_type, crypto::families::box_xsalsa20poly1305>);
static_assert(std::is_same_v<sealed_box::family_type, crypto::families::sealed_box>);
static_assert(std::is_same_v<sealed_box::name_type, crypto::families::sealed_box>);
static_assert(crypto::supports_v<box, crypto::backends::sodium>);
static_assert(crypto::supports_v<box_xchacha, crypto::backends::sodium>);
static_assert(crypto::supports_v<sealed_box, crypto::backends::sodium>);
static_assert(box::key_size == 32 && box::iv_size == 24 && box::tag_size == 16);
static_assert(box_xchacha::key_size == 32 && box_xchacha::iv_size == 24 &&
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
        .iv = nacl_nonce,
        .additional_data = "",
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
        .iv = nacl_nonce,
        .additional_data = "",
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
        .iv = nacl_nonce,
        .additional_data = "",
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
        .iv = nacl_nonce,
        .additional_data = "",
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
 * How the checks of support/aead_checks.hpp reach a box: its "key" is the secret key followed
 * by the peer's public key, 64 bytes, and it has no additional data, which its calls do not
 * take (the checks pass none).
 */
template <class Box>
struct box_calls {
    using object = Box;
    static constexpr std::size_t key_size = 64;
    static constexpr std::size_t iv_size = Box::iv_size;
    static constexpr std::size_t tag_size = Box::tag_size;
    static constexpr bool has_additional_data = false;
    static constexpr bool takes_additional_data = false;
    static constexpr bool one_key = false;

    static auto from_key(std::span<std::uint8_t const> key) {
        auto const split = std::min<std::size_t>(key.size(), 32);
        return Box::from_keys(key.first(split), key.subspan(split));
    }

    static auto seal(Box& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data) {
        BOOST_TEST(additional_data.empty());
        return made.seal(iv, data);
    }

    static auto open(Box& made, std::span<std::uint8_t const> iv,
                     std::span<std::uint8_t const> additional_data, std::span<std::uint8_t> data,
                     std::span<std::uint8_t const> tag) {
        BOOST_TEST(additional_data.empty());
        return made.open(iv, data, tag);
    }
};

/**
 * from_keys' guards: the secret key's size (invalid_key_size) before the peer key's
 * (invalid_public_key); a peer key of small order, as libsodium's beforenm refuses it
 * (weak_public_key), and the all-zero point.
 */
template <class Box>
void check_box_from_keys() {
    auto const secret = from_hex(alice_secret);
    auto const peer = from_hex(bob_public);
    for (std::size_t const size : {std::size_t{0}, std::size_t{31}, std::size_t{33}}) {
        std::vector<std::uint8_t> const wrong(size, 7);
        BOOST_TEST(Box::from_keys(wrong, peer).error() == crypto::error::invalid_key_size);
        BOOST_TEST(Box::from_keys(secret, wrong).error() == crypto::error::invalid_public_key);
        BOOST_TEST(Box::from_keys(wrong, wrong).error() == crypto::error::invalid_key_size);
    }
    BOOST_TEST(Box::from_keys(secret, from_hex(small_order)).error() ==
               crypto::error::weak_public_key);
    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(Box::from_keys(secret, zero).error() == crypto::error::weak_public_key);
    BOOST_TEST(Box::from_keys(secret, peer).has_value());
}

/**
 * A box is the secret box of the same construction under its precomputed key: libsodium's
 * crypto_box_afternm is crypto_secretbox, and its XChaCha20 twin the XChaCha20 secret box.
 */
template <class Box, class Secretbox>
void check_box_is_secretbox(std::string_view key) {
    auto made_box = Box::from_keys(from_hex(alice_secret), from_hex(bob_public));
    auto made_secretbox = Secretbox::from_key(from_hex(key));
    if (!BOOST_TEST(made_box.has_value()) || !BOOST_TEST(made_secretbox.has_value())) {
        return;
    }
    auto const iv = from_hex(nacl_nonce);
    auto by_box = from_hex(nacl_message);
    auto by_secretbox = by_box;
    auto const box_tag = made_box->seal(iv, by_box);
    auto const secretbox_tag = made_secretbox->seal(iv, {}, by_secretbox);
    BOOST_TEST(box_tag && secretbox_tag && to_hex(*box_tag) == to_hex(*secretbox_tag));
    BOOST_TEST(by_box == by_secretbox);
}

/** A recipient's key pair: its secret key's bytes all `fill`, and its X25519 public key. */
struct recipient {
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, 32> public_key{};

    explicit recipient(std::uint8_t fill) {
        secret_key.fill(fill);
        auto const made = crypto::curves::x25519::public_key(secret_key);
        BOOST_TEST(made.has_value());
        if (made) {
            public_key = *made;
        }
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
void expect_sealed_refused(std::span<std::uint8_t const> public_key,
                           std::span<std::uint8_t const> secret_key,
                           std::span<std::uint8_t const> sealed) {
    std::vector<std::uint8_t> out(sealed.size() - sealed_box::overhead, 0x77);
    BOOST_TEST(sealed_box::open(public_key, secret_key, sealed, out).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(webcpp::test::all_zero(out));
}

/**
 * libsodium's tv1: a message sealed to a public key opens with the recipient's key pair alone;
 * another key pair, the keys swapped, any byte changed and a sealed box one byte shorter are
 * refused, the output zeroed; two seals of one message differ, each carrying its own ephemeral
 * public key first.
 */
void check_sealed_box() {
    recipient const bob(0x11);
    recipient const eve(0x22);
    auto const plain = sealed_message(100);
    std::vector<std::uint8_t> sealed(plain.size() + sealed_box::overhead);
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, sealed).has_value());
    BOOST_TEST(!std::equal(bob.public_key.begin(), bob.public_key.end(), sealed.begin()));
    std::vector<std::uint8_t> opened(plain.size());
    BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, sealed, opened).has_value());
    BOOST_TEST(opened == plain);
    // Another seal of the same message, under another ephemeral key pair.
    std::vector<std::uint8_t> again(sealed.size());
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, again).has_value());
    BOOST_TEST(again != sealed);
    BOOST_TEST(!std::equal(again.begin(), again.begin() + 32, sealed.begin()));
    // Another key pair, Eve's secret key with Bob's public key, and Bob's keys swapped.
    expect_sealed_refused(eve.public_key, eve.secret_key, sealed);
    expect_sealed_refused(bob.public_key, eve.secret_key, sealed);
    expect_sealed_refused(eve.public_key, bob.secret_key, sealed);
    expect_sealed_refused(bob.secret_key, bob.public_key, sealed);
    // Any byte changed: the ephemeral public key, the tag or the ciphertext.
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        auto changed = sealed;
        changed[i] ^= 0x40U;
        expect_sealed_refused(bob.public_key, bob.secret_key, changed);
    }
    // One byte shorter.
    expect_sealed_refused(bob.public_key, bob.secret_key,
                          std::span(sealed).first(sealed.size() - 1));
    // The refusals end nothing: the sealed box still opens.
    BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, sealed, opened).has_value());
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
    BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, buffer, opened).has_value());
    BOOST_TEST(opened == plain);
    std::array<std::uint8_t, sealed_box::overhead> empty_sealed{};
    BOOST_TEST(sealed_box::seal(bob.public_key, {}, empty_sealed).has_value());
    BOOST_TEST(
        sealed_box::open(bob.public_key, bob.secret_key, empty_sealed, std::span<std::uint8_t>())
            .has_value());
    empty_sealed[40] ^= 1U;
    BOOST_TEST(
        sealed_box::open(bob.public_key, bob.secret_key, empty_sealed, std::span<std::uint8_t>())
            .error() == crypto::error::authentication_failed);
}

/**
 * The guards, in their order: the sizes first (invalid_input_size: an output not of the
 * message's size plus the overhead, a sealed box shorter than the overhead, an output not of
 * its size less the overhead), then the keys (invalid_public_key, invalid_key_size); each
 * refusal leaves the output untouched. A recipient key of small order is refused when sealing
 * (weak_public_key), the output zeroed.
 */
void check_sealed_box_guards() {
    recipient const bob(0x44);
    auto const plain = sealed_message(10);
    std::vector<std::uint8_t> out(plain.size() + sealed_box::overhead, 0x55);
    auto const untouched = out;
    std::vector<std::uint8_t> const short_key(31, 9);
    for (std::size_t const size :
         {std::size_t{0}, std::size_t{47}, plain.size() + 47, plain.size() + 49}) {
        std::vector<std::uint8_t> wrong(size, 0x55);
        auto const wrong_untouched = wrong;
        BOOST_TEST(sealed_box::seal(bob.public_key, plain, wrong).error() ==
                   crypto::error::invalid_input_size);
        BOOST_TEST(sealed_box::seal(short_key, plain, wrong).error() ==
                   crypto::error::invalid_input_size);
        BOOST_TEST(wrong == wrong_untouched);
    }
    BOOST_TEST(sealed_box::seal(short_key, plain, out).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(out == untouched);
    BOOST_TEST(sealed_box::seal(bob.public_key, plain, out).has_value());
    auto const sealed = out;
    std::vector<std::uint8_t> opened(plain.size(), 0x66);
    auto const opened_untouched = opened;
    // A sealed box shorter than the overhead, and outputs of other sizes than it holds.
    for (std::size_t const size : {std::size_t{0}, std::size_t{47}}) {
        std::vector<std::uint8_t> const too_short(size, 1);
        BOOST_TEST(
            sealed_box::open(bob.public_key, bob.secret_key, too_short, std::span<std::uint8_t>())
                .error() == crypto::error::invalid_input_size);
    }
    for (std::size_t const size : {std::size_t{0}, plain.size() - 1, plain.size() + 1}) {
        std::vector<std::uint8_t> wrong(size, 0x66);
        BOOST_TEST(sealed_box::open(bob.public_key, bob.secret_key, sealed, wrong).error() ==
                   crypto::error::invalid_input_size);
        BOOST_TEST(sealed_box::open(short_key, short_key, sealed, wrong).error() ==
                   crypto::error::invalid_input_size);
    }
    BOOST_TEST(sealed_box::open(short_key, bob.secret_key, sealed, opened).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(sealed_box::open(bob.public_key, short_key, sealed, opened).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(opened == opened_untouched);
    // A recipient key of small order: libsodium's box refuses it, and the output is zeroed.
    BOOST_TEST(sealed_box::seal(from_hex(small_order), plain, out).error() ==
               crypto::error::weak_public_key);
    BOOST_TEST(webcpp::test::all_zero(out));
}

}  // namespace

int main() {
    webcpp::test::check_aead_with<box_calls<box>>(box_cases);
    webcpp::test::check_aead_with<box_calls<box_xchacha>>(box_xchacha_cases);
    check_box_from_keys<box>();
    check_box_from_keys<box_xchacha>();
    check_box_is_secretbox<box, crypto::ciphers::secretbox<>>(box_key);
    check_box_is_secretbox<box_xchacha, crypto::ciphers::secretbox_xchacha20poly1305<>>(
        box_xchacha_key);
    check_sealed_box();
    check_sealed_box_edges();
    check_sealed_box_guards();
    return webcpp::test::exit_status(boost::report_errors());
}
