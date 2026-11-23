// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsodium's secret boxes, crypto_secretbox (XSalsa20-Poly1305) and
// crypto_secretbox_xchacha20poly1305, through their default types,
// secret_key_encryption::secretbox<> and secret_key_encryption::secretbox_xchacha20poly1305<>,
// whose backend is libsodium on every target (design D5, D11): NaCl's case of libsodium's
// test/default/secretbox.c and .exp and libsodium's XChaCha20 cases of test/default/xchacha20.c;
// seal(nonce, data), the member and the box form secret_key_encryption::seal(box, nonce, data),
// named in full and found unqualified by argument-dependent lookup, giving the ciphertext and the
// tag libsodium's crypto_secretbox_detached and crypto_secretbox_xchacha20poly1305_detached give,
// called here, and open and secret_key_encryption::open opening them; no seal or open that takes
// associated data; a failed open, through the member and the box form alike (a changed byte of the
// ciphertext, the tag or the nonce: authentication_failed, the data zeroed; a short tag, a long
// nonce, a box moved from: refused, the data untouched); and every guard, tampering, moves, empty
// inputs and aliasing spans of support/aead_checks.hpp, through an adapter that passes no
// associated data. Their limit, 2^64 - 17 bytes, no span reaches.

#include <webcpp/crypto/secret_key_encryption/authenticated_box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aead_checks.hpp"

#include <boost/core/lightweight_test.hpp>

#include <sodium/crypto_secretbox.h>  // its MESSAGEBYTES_MAX and detached function
#include <sodium/crypto_secretbox_xchacha20poly1305.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secret_key_encryption = webcpp::crypto::secret_key_encryption;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

namespace {

using secretbox = secret_key_encryption::secretbox<>;
using secretbox_xchacha = secret_key_encryption::secretbox_xchacha20poly1305<>;

// The default is libsodium on every target, the one backend of both families, and the types
// name their family and their algorithm as the capability table does.
static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::secretbox_xsalsa20poly1305>,
                   crypto::backends::sodium>);
static_assert(
    std::is_same_v<crypto::default_backend_t<crypto::families::secretbox_xchacha20poly1305>,
                   crypto::backends::sodium>);
static_assert(
    std::is_same_v<secretbox,
                   secret_key_encryption::basic_secretbox<
                       crypto::families::secretbox_xsalsa20poly1305, crypto::backends::sodium>>);
static_assert(
    std::is_same_v<secretbox_xchacha,
                   secret_key_encryption::basic_secretbox<
                       crypto::families::secretbox_xchacha20poly1305, crypto::backends::sodium>>);
static_assert(secret_key_encryption::authenticated_box<secretbox> &&
              secret_key_encryption::authenticated_box<secretbox_xchacha>);
static_assert(std::is_same_v<secretbox::family_type, crypto::families::secretbox_xsalsa20poly1305>);
static_assert(std::is_same_v<secretbox::name_type, crypto::families::secretbox_xsalsa20poly1305>);
static_assert(crypto::supports_v<secretbox, crypto::backends::sodium>);
static_assert(crypto::supports_v<secretbox_xchacha, crypto::backends::sodium>);
static_assert(secretbox::key_size == 32 && secretbox::nonce_size == 24 &&
              secretbox::tag_size == 16);
static_assert(secretbox_xchacha::key_size == 32 && secretbox_xchacha::nonce_size == 24 &&
              secretbox_xchacha::tag_size == 16);
static_assert(secretbox::max_message_size == ~std::uint64_t{0} - 16);
// libsodium's own limit on a 64-bit target; on a 32-bit one libsodium's is the smaller,
// 2^32 - 17, as the Doc Comment says.
// NOLINTBEGIN(bugprone-branch-clone): libsodium's limit is its SODIUM_MIN macro, a ?: whose two
// operands are the same value on 64-bit Linux.
static_assert(sizeof(std::size_t) != 8 ||
              secretbox::max_message_size == crypto_secretbox_MESSAGEBYTES_MAX);
static_assert(sizeof(std::size_t) == 8 || crypto_secretbox_MESSAGEBYTES_MAX == 0xffffffffU - 16);
// NOLINTEND(bugprone-branch-clone)

/** Whether `Box` seals with associated data, as an AEAD does: a secret box does not. */
template <class Box>
concept seals_with_associated_data = requires(Box& keyed, std::span<std::uint8_t const> nonce_bytes,
                                              std::span<std::uint8_t const> associated_data_bytes,
                                              std::span<std::uint8_t> data_bytes) {
    keyed.seal(nonce_bytes, associated_data_bytes, data_bytes);
};

/** Whether `Box` opens with associated data, as an AEAD does: a secret box does not. */
template <class Box>
concept opens_with_associated_data =
    requires(Box& keyed, std::span<std::uint8_t const> nonce_bytes,
             std::span<std::uint8_t const> associated_data_bytes,
             std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes) {
        keyed.open(nonce_bytes, associated_data_bytes, data_bytes, tag_bytes);
    };

static_assert(!seals_with_associated_data<secretbox> && !opens_with_associated_data<secretbox>);
static_assert(!seals_with_associated_data<secretbox_xchacha> &&
              !opens_with_associated_data<secretbox_xchacha>);

/**
 * How the checks of support/aead_checks.hpp reach a secret box: one key of `key_size` bytes, and
 * no associated data, which its calls do not take (the checks pass none).
 */
template <class Box>
struct secretbox_calls {
    using object = Box;
    static constexpr std::size_t key_size = Box::key_size;
    static constexpr std::size_t nonce_size = Box::nonce_size;
    static constexpr std::size_t tag_size = Box::tag_size;
    static constexpr bool has_additional_data = false;
    static constexpr bool one_key = true;

    static auto from_key(std::span<std::uint8_t const> key) { return Box::from_key(key); }

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

/**
 * NaCl's secret box, libsodium's test/default/secretbox.c: its key ("firstkey"), nonce and
 * the 131 bytes after the 32 zero bytes of its message; secretbox.exp prints the tag, then the
 * ciphertext, once sealed apart and once in place.
 */
constexpr std::array<webcpp::test::aead_case, 1> secretbox_cases{
    webcpp::test::aead_case{
        .key = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389",
        .nonce = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
        .associated_data = "",
        .plaintext =
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac7"
            "28d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556a"
            "d6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f9377638"
            "48645e0705",
        .ciphertext =
            "8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7"
            "f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368"
            "517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb4"
            "5a74e355a5",
        .tag = "f3ffc7703f9400e52a7dfb4b3d3305d9",
    },
};

/**
 * libsodium's XChaCha20 secret boxes, test/default/xchacha20.c's tv_secretbox_xchacha20poly1305:
 * its first, second and seventh cases (an empty message among them), each tag the first 16
 * bytes of the case's output and the ciphertext the rest. The first carries a message: the
 * checks tamper with it.
 */
constexpr std::array<webcpp::test::aead_case, 3> secretbox_xchacha_cases{
    webcpp::test::aead_case{
        .key = "d3c71d54e6b13506e07aa2e7b412a17a7a1f34df3d3148cd3f45b91ccaa5f4d9",
        .nonce = "943b454a853aa514c63cf99b1e197bbb99da24b2e2d93e47",
        .associated_data = "",
        .plaintext = "76bd706e07741e713d90efdb34ad202067263f984942aae8bda159f30dfccc72200f8093520b"
                     "85c5ad124ff7c8b2d920946e5cfff4b819abf84c7b35a6205ca72c9f8747c3044dd73fb4beb"
                     "da1b476",
        .ciphertext = "1c6f526d2c19557cf8bd270fcde43fba1d88890663f7b2f5c6b1d7deccf5c91b4df5865dc55c"
                      "c7e04d6793fc2db8f9e3b418f95cb796d67a7f3f7e097150cb607c435dacf82eac3d669866e"
                      "5092ace",
        .tag = "0384276f1cfa5c82c3e58f0f2acc1f82",
    },
    webcpp::test::aead_case{
        .key = "065ff46a9dddb1ab047ee5914d6d575a828b8cc1f454b24e8cd0f57efdc49a34",
        .nonce = "f83262646ce01293b9923a65a073df78c54b2e799cd6c4e5",
        .associated_data = "",
        .plaintext = "",
        .ciphertext = "",
        .tag = "4c72340416339dcdea01b760db5adaf7",
    },
    webcpp::test::aead_case{
        .key = "10c0ad4054b48d7d1de1d9ab6f782ca883d886573e9d18c1d47b6ee6b5208189",
        .nonce = "977edf57428d0e0247a3c88c9a9ec321bbaae1a4da8353b5",
        .associated_data = "",
        .plaintext = "518e4a27949812424b2a381c3efea6055ee5e75eff",
        .ciphertext = "b05a15f8edb68b35773e81ac2aca18e9be53416f9a",
        .tag = "0c801a037c2ed0500d6ef68e8d195ece",
    },
};

/** libsodium's detached seal of a family, which the checks call to compare. */
template <class Box>
int sodium_detached(unsigned char* ciphertext, unsigned char* tag, unsigned char const* message,
                    unsigned long long message_size, unsigned char const* nonce,
                    unsigned char const* key) {
    if constexpr (std::is_same_v<typename Box::family_type,
                                 crypto::families::secretbox_xsalsa20poly1305>) {
        return crypto_secretbox_detached(ciphertext, tag, message, message_size, nonce, key);
    } else {
        return crypto_secretbox_xchacha20poly1305_detached(ciphertext, tag, message, message_size,
                                                           nonce, key);
    }
}

/**
 * seal(nonce, data), the member and the box form, gives libsodium's detached ciphertext and tag
 * for one message, a message of no byte included; open and the box form open them back.
 */
template <class Box>
void check_against_sodium(std::string_view key_hex, std::string_view nonce_hex,
                          std::string_view message_hex) {
    auto const key = from_hex(key_hex);
    auto const nonce = from_hex(nonce_hex);
    auto const message = from_hex(message_hex);
    auto made = Box::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto expected = message;
    std::array<unsigned char, 16> expected_tag{};
    BOOST_TEST_EQ(sodium_detached<Box>(expected.data(), expected_tag.data(), message.data(),
                                       message.size(), nonce.data(), key.data()),
                  0);
    auto by_member = message;
    auto by_free = message;
    auto const member_tag = made->seal(nonce, by_member);
    auto const free_tag = secret_key_encryption::seal(*made, nonce, by_free);
    static_assert(std::is_same_v<decltype(free_tag), decltype(member_tag)>);
    if (!BOOST_TEST(member_tag.has_value()) || !BOOST_TEST(free_tag.has_value())) {
        return;
    }
    BOOST_TEST(by_member == expected);
    BOOST_TEST(by_free == expected);
    // Unqualified, argument-dependent lookup finds the box forms in the box's namespace.
    auto by_lookup = message;
    auto const lookup_tag = seal(*made, nonce, by_lookup);
    BOOST_TEST(lookup_tag.has_value() && *lookup_tag == *member_tag);
    BOOST_TEST(by_lookup == expected);
    BOOST_TEST(open(*made, nonce, by_lookup,
                    std::span<std::uint8_t const>(lookup_tag->data(), lookup_tag->size()))
                   .has_value());
    BOOST_TEST(by_lookup == message);
    BOOST_TEST_EQ(to_hex(*member_tag), to_hex(expected_tag));
    BOOST_TEST_EQ(to_hex(*free_tag), to_hex(expected_tag));
    auto const tag = std::span<std::uint8_t const>(member_tag->data(), member_tag->size());
    BOOST_TEST(made->open(nonce, by_member, tag).has_value());
    BOOST_TEST(secret_key_encryption::open(*made, nonce, by_free, tag).has_value());
    BOOST_TEST(by_member == message);
    BOOST_TEST(by_free == message);
}

/** A message, its seal under one box, and the bytes the open checks compare it to. */
template <class Box>
struct sealed_message {
    /** The nonce of the seal. */
    std::array<std::uint8_t, Box::nonce_size> nonce{};
    /** The plaintext. */
    std::array<std::uint8_t, 21> message{};
    /** The ciphertext. */
    std::array<std::uint8_t, 21> sealed{};
    /** The tag. */
    std::array<std::uint8_t, Box::tag_size> tag{};
};

/**
 * The failed opens of one sealed message, through the member or the box form: a changed byte of
 * the ciphertext, of the tag or of the nonce fails with authentication_failed and zeroes the data;
 * a short tag and a long nonce are refused, the data untouched; the message then opens.
 */
template <class Box, class Open>
void open_failures_through(sealed_message<Box> const& sealed, Open open_with) {
    std::array<std::uint8_t, 21> const zeros{};
    auto changed_data = sealed.sealed;
    changed_data[3] ^= 0x01U;
    BOOST_TEST(open_with(sealed.nonce, changed_data, sealed.tag).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(changed_data == zeros);
    auto changed_tag = sealed.tag;
    changed_tag[15] ^= 0x80U;
    auto data = sealed.sealed;
    BOOST_TEST(open_with(sealed.nonce, data, changed_tag).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(data == zeros);
    auto changed_nonce = sealed.nonce;
    changed_nonce[0] ^= 0x01U;
    data = sealed.sealed;
    BOOST_TEST(open_with(changed_nonce, data, sealed.tag).error() ==
               crypto::error::authentication_failed);
    BOOST_TEST(data == zeros);
    data = sealed.sealed;
    BOOST_TEST(open_with(sealed.nonce, data, std::span(sealed.tag).first(15)).error() ==
               crypto::error::invalid_tag_size);
    std::array<std::uint8_t, Box::nonce_size + 1> const long_nonce{};
    BOOST_TEST(open_with(long_nonce, data, sealed.tag).error() ==
               crypto::error::invalid_nonce_size);
    BOOST_TEST(data == sealed.sealed);
    BOOST_TEST(open_with(sealed.nonce, data, sealed.tag).has_value());
    BOOST_TEST(data == sealed.message);
}

/**
 * A failed open, through the member and the box form alike (Review Focus 3): the failures of
 * open_failures_through, then a box moved from, refused (invalid_state) with the data untouched.
 */
template <class Box>
void open_failures() {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x5a);
    auto made = Box::from_key(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    sealed_message<Box> sealed;
    sealed.nonce.fill(0x11);
    std::string_view const text = "attack at dawn tomoro";
    std::copy_n(text.begin(), sealed.message.size(), sealed.message.begin());
    sealed.sealed = sealed.message;
    auto const sealed_tag = made->seal(sealed.nonce, sealed.sealed);
    if (!BOOST_TEST(sealed_tag.has_value())) {
        return;
    }
    std::copy_n(sealed_tag->data(), sealed.tag.size(), sealed.tag.begin());
    open_failures_through<Box>(sealed, [&made](auto const& nonce, auto& data, auto const& tag) {
        return made->open(nonce, data, tag);
    });
    open_failures_through<Box>(sealed, [&made](auto const& nonce, auto& data, auto const& tag) {
        return secret_key_encryption::open(*made, nonce, data, tag);
    });
    Box const moved = std::move(*made);
    auto data = sealed.sealed;
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from box's refusal
    BOOST_TEST(made->open(sealed.nonce, data, sealed.tag).error() == crypto::error::invalid_state);
    BOOST_TEST(secret_key_encryption::open(*made, sealed.nonce, data, sealed.tag).error() ==
               crypto::error::invalid_state);
    BOOST_TEST(data == sealed.sealed);
}

}  // namespace

int main() {
    webcpp::test::check_aead_with<secretbox_calls<secretbox>>(secretbox_cases);
    webcpp::test::check_aead_with<secretbox_calls<secretbox_xchacha>>(secretbox_xchacha_cases);
    for (auto const& c : secretbox_cases) {
        check_against_sodium<secretbox>(c.key, c.nonce, c.plaintext);
    }
    for (auto const& c : secretbox_xchacha_cases) {
        check_against_sodium<secretbox_xchacha>(c.key, c.nonce, c.plaintext);
    }
    open_failures<secretbox>();
    open_failures<secretbox_xchacha>();
    return webcpp::test::exit_status(boost::report_errors());
}
