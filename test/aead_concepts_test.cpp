// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AEAD and box concepts (design D5, R21): secret_key_encryption::aead::cipher, a one-shot
// AEAD with associated data (its sizes, its tag type, from_key, seal and open);
// secret_key_encryption::aead::streaming_cipher, a cipher that also seals and opens in pieces with
// AES-GCM's members; secret_key_encryption::authenticated_box, authenticated encryption without
// associated data. D5's table on the types' own backends: AES-GCM a streaming_cipher, with
// 128- and 256-bit keys, the three ChaCha20-Poly1305 AEADs ciphers and no streaming_cipher, the two
// secret boxes and the two crypto_boxes authenticated_boxes; no type of the table is both a
// cipher and an authenticated_box. Stand-ins lacking one member each, or giving another type,
// give each concept's verdict. The box forms take no AEAD, and the AEAD forms take a cipher; a box
// given to the AEAD forms stops the build, which the message test seal_box_associated_data checks.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/secret_key_encryption/aead.hpp>
#include <webcpp/crypto/secret_key_encryption/authenticated_box.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto = webcpp::crypto;
namespace aead = webcpp::crypto::secret_key_encryption::aead;
namespace secret_key_encryption = webcpp::crypto::secret_key_encryption;

namespace {

using span_const = std::span<std::uint8_t const>;
using span_mutable = std::span<std::uint8_t>;
using tag_type = boost::hash2::digest<16>;

// Every member of cipher: a one-shot AEAD.
struct complete_cipher {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    static boost::system::result<complete_cipher> from_key(span_const) noexcept;
    boost::system::result<result_type> seal(span_const, span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_const, span_mutable, span_const) noexcept;
};

// A cipher without open: no cipher.
struct cipher_without_open {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    static boost::system::result<cipher_without_open> from_key(span_const) noexcept;
    boost::system::result<result_type> seal(span_const, span_const, span_mutable) noexcept;
};

// A cipher without from_key: no cipher.
struct cipher_without_from_key {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    boost::system::result<result_type> seal(span_const, span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_const, span_mutable, span_const) noexcept;
};

// A cipher whose seal gives the tag bare, not a result: no cipher.
struct cipher_with_bare_tag {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 12;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    static boost::system::result<cipher_with_bare_tag> from_key(span_const) noexcept;
    result_type seal(span_const, span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_const, span_mutable, span_const) noexcept;
};

// A cipher without nonce_size: no cipher (the sizes are spelled out, design D11).
struct cipher_without_nonce_size {
    [[maybe_unused]] static constexpr std::size_t key_size = 32;
    [[maybe_unused]] static constexpr std::size_t iv_size = 12;
    [[maybe_unused]] static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    static boost::system::result<cipher_without_nonce_size> from_key(span_const) noexcept;
    boost::system::result<result_type> seal(span_const, span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_const, span_mutable, span_const) noexcept;
};

// A cipher with AES-GCM's incremental members: a streaming_cipher.
struct complete_streaming_cipher : complete_cipher {
    static boost::system::result<complete_streaming_cipher> from_key(span_const) noexcept;
    boost::system::result<void> begin_seal(span_const, span_const) noexcept;
    boost::system::result<void> update(span_mutable) noexcept;
    boost::system::result<result_type> result() noexcept;
    boost::system::result<void> begin_open(span_const, span_const) noexcept;
    boost::system::result<void> authenticate(span_const) noexcept;
    boost::system::result<void> decrypt(span_mutable) noexcept;
    boost::system::result<void> verify(span_const) noexcept;
    boost::system::result<void> end_open() noexcept;
};

// The same without verify: a cipher and no streaming_cipher.
struct streaming_cipher_without_verify : complete_cipher {
    static boost::system::result<streaming_cipher_without_verify> from_key(span_const) noexcept;
    boost::system::result<void> begin_seal(span_const, span_const) noexcept;
    boost::system::result<void> update(span_mutable) noexcept;
    boost::system::result<result_type> result() noexcept;
    boost::system::result<void> begin_open(span_const, span_const) noexcept;
    boost::system::result<void> authenticate(span_const) noexcept;
    boost::system::result<void> decrypt(span_mutable) noexcept;
    boost::system::result<void> end_open() noexcept;
};

// Every member of authenticated_box, and no factory, which the concept does not ask.
struct complete_box {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 24;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    boost::system::result<result_type> seal(span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_mutable, span_const) noexcept;
};

// A box whose open does not take the tag: no authenticated_box.
struct box_without_tag {
    static constexpr std::size_t key_size = 32;
    static constexpr std::size_t nonce_size = 24;
    static constexpr std::size_t tag_size = 16;
    using result_type = tag_type;
    boost::system::result<result_type> seal(span_const, span_mutable) noexcept;
    boost::system::result<void> open(span_const, span_mutable) noexcept;
};

static_assert(aead::cipher<complete_cipher>);
static_assert(!aead::streaming_cipher<complete_cipher>);
static_assert(!secret_key_encryption::authenticated_box<complete_cipher>);
static_assert(!aead::cipher<cipher_without_open>);
static_assert(!aead::cipher<cipher_without_from_key>);
static_assert(!aead::cipher<cipher_with_bare_tag>);
static_assert(!aead::cipher<cipher_without_nonce_size>);
static_assert(aead::streaming_cipher<complete_streaming_cipher>);
static_assert(aead::cipher<streaming_cipher_without_verify>);
static_assert(!aead::streaming_cipher<streaming_cipher_without_verify>);
static_assert(secret_key_encryption::authenticated_box<complete_box>);
static_assert(!aead::cipher<complete_box>);
static_assert(!secret_key_encryption::authenticated_box<box_without_tag>);

// D5's table, on each type's own backend.
using gcm_bearssl = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;
using gcm128_bearssl = crypto::ciphers::gcm<crypto::ciphers::aes128<crypto::backends::bearssl>>;
using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::sodium>;
using chacha_original = crypto::ciphers::chacha20_poly1305_original<crypto::backends::sodium>;
using xchacha = crypto::ciphers::xchacha20_poly1305<crypto::backends::sodium>;
using chacha_bearssl = crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>;
using secretbox = secret_key_encryption::secretbox<crypto::backends::sodium>;
using secretbox_xchacha =
    secret_key_encryption::secretbox_xchacha20poly1305<crypto::backends::sodium>;
using crypto::public_key_encryption::box;
using box_xchacha = crypto::public_key_encryption::box_xchacha20poly1305;

static_assert(aead::streaming_cipher<gcm_bearssl>);
static_assert(aead::streaming_cipher<gcm128_bearssl>);
static_assert(aead::cipher<chacha> && !aead::streaming_cipher<chacha>);
static_assert(aead::cipher<chacha_original> && !aead::streaming_cipher<chacha_original>);
static_assert(aead::cipher<xchacha> && !aead::streaming_cipher<xchacha>);
static_assert(aead::cipher<chacha_bearssl> && !aead::streaming_cipher<chacha_bearssl>);
static_assert(secret_key_encryption::authenticated_box<secretbox>);
static_assert(secret_key_encryption::authenticated_box<secretbox_xchacha>);
static_assert(secret_key_encryption::authenticated_box<box>);
static_assert(secret_key_encryption::authenticated_box<box_xchacha>);

/** Whether `Type` is both a cipher and an authenticated_box: none of D5's table is. */
template <class Type>
constexpr bool both = aead::cipher<Type> && secret_key_encryption::authenticated_box<Type>;

static_assert(!both<gcm_bearssl> && !both<chacha> && !both<chacha_original> && !both<xchacha>);
static_assert(!both<secretbox> && !both<secretbox_xchacha> && !both<box> && !both<box_xchacha>);

/** Whether the box forms take `Type`: a box's seal without associated data. */
template <class Type>
concept box_sealable = requires(Type& keyed, span_const nonce_bytes, span_mutable data_bytes) {
    secret_key_encryption::seal(keyed, nonce_bytes, data_bytes);
};

/** Whether the AEAD forms take `Type` with a cipher's arguments. */
template <class Type>
concept aead_sealable = requires(Type& keyed, span_const nonce_bytes,
                                 span_const associated_data_bytes, span_mutable data_bytes) {
    aead::seal(keyed, nonce_bytes, associated_data_bytes, data_bytes);
};

// The box forms take a box and no AEAD; the AEAD forms take a cipher and no stand-in that is
// neither. (A box given to the AEAD forms is a viable call whose body stops the build: the
// message test seal_box_associated_data.)
static_assert(box_sealable<secretbox> && box_sealable<box> && box_sealable<complete_box>);
static_assert(!box_sealable<chacha> && !box_sealable<gcm_bearssl> &&
              !box_sealable<complete_cipher>);
static_assert(aead_sealable<chacha> && aead_sealable<gcm_bearssl> &&
              aead_sealable<complete_cipher>);
static_assert(!aead_sealable<cipher_without_open>);

/**
 * Seals and opens through the concept alone: a generic program over every cipher.
 *
 * @tparam Cipher A cipher.
 * @return Whether the message came back.
 */
// tag::generic[]
template <aead::cipher Cipher>
bool round_trip_cipher() {
    std::array<std::uint8_t, Cipher::key_size> key{};
    key.fill(7);
    std::array<std::uint8_t, Cipher::nonce_size> const nonce{1};
    std::array<std::uint8_t, 3> const associated_data{'a', 'd', '!'};
    auto made = Cipher::from_key(key);
    if (!made) {
        return false;
    }
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    auto const original = data;
    auto const tag = aead::seal(*made, nonce, associated_data, data);
    if (!tag || data == original) {
        return false;
    }
    return aead::open(*made, nonce, associated_data, data, std::span(tag->data(), tag->size())) &&
           data == original;
}

// end::generic[]

/**
 * Seals and opens through the box concept alone, a box made by its own factory.
 *
 * @tparam Box An authenticated_box.
 * @param made_box The box.
 * @return Whether the message came back.
 */
template <secret_key_encryption::authenticated_box Box>
bool round_trip_box(Box& made_box) {
    std::array<std::uint8_t, Box::nonce_size> const nonce{2};
    std::array<std::uint8_t, 5> data{'w', 'o', 'r', 'l', 'd'};
    auto const original = data;
    auto const tag = secret_key_encryption::seal(made_box, nonce, data);
    if (!tag || data == original) {
        return false;
    }
    return secret_key_encryption::open(made_box, nonce, data,
                                       std::span(tag->data(), tag->size())) &&
           data == original;
}

/** The ciphers of D5's table seal and open through their concept alone. */
void ciphers_round_trip() {
    BOOST_TEST(round_trip_cipher<gcm_bearssl>());
    BOOST_TEST(round_trip_cipher<chacha>());
    BOOST_TEST(round_trip_cipher<chacha_original>());
    BOOST_TEST(round_trip_cipher<xchacha>());
    BOOST_TEST(round_trip_cipher<chacha_bearssl>());
}

/** The two secret boxes seal and open through the box concept alone. */
void secretboxes_round_trip() {
    std::array<std::uint8_t, 32> key{};
    key.fill(9);
    auto made_secretbox = secretbox::from_key(key);
    auto made_secretbox_xchacha = secretbox_xchacha::from_key(key);
    if (BOOST_TEST(made_secretbox.has_value()) && BOOST_TEST(made_secretbox_xchacha.has_value())) {
        BOOST_TEST(round_trip_box(*made_secretbox));
        BOOST_TEST(round_trip_box(*made_secretbox_xchacha));
    }
}

/** The two crypto_boxes, a key pair's with its own public key, through the box concept alone. */
void boxes_round_trip() {
    std::array<std::uint8_t, 32> key{};
    key.fill(9);
    auto const own = crypto::curves::x25519::keypair::from_secret(key);
    if (!BOOST_TEST(own.has_value())) {
        return;
    }
    auto const own_public = own->public_key();
    if (!BOOST_TEST(own_public.has_value())) {
        return;
    }
    auto made_box = box::from_keys(*own, *own_public);
    auto made_box_xchacha = box_xchacha::from_keys(*own, *own_public);
    if (BOOST_TEST(made_box.has_value()) && BOOST_TEST(made_box_xchacha.has_value())) {
        BOOST_TEST(round_trip_box(*made_box));
        BOOST_TEST(round_trip_box(*made_box_xchacha));
    }
}

}  // namespace

int main() {
    ciphers_round_trip();
    secretboxes_round_trip();
    boxes_round_trip();
    return webcpp::test::exit_status(boost::report_errors());
}
