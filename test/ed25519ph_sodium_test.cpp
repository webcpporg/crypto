// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519ph on libsodium, the scheme crypto::eddsa_prehashed and the streaming signer
// curves::ed25519::prehashed_signer:
// - rfc8032_ph: RFC 8032 section 7.3's test, the message "abc" given to the signer in one piece and
//   in two, signed into the RFC's signature, a curves::ed25519::signature, and verified with
//   verify(signature, public_key), the signature first, of that type, and the key a
//   curves::ed25519::public_key; the key's bytes, and 63 bytes, refused as a signature by
//   from_bytes; a signature changed in one bit and a different message refused.
// - rfc8032_ph_scheme: the same key pair signs crypto::prehashed{sha512("abc")} with
//   sign(crypto::eddsa_prehashed, ...) into the RFC's signature, which crypto::verify and the
//   key's verify accept under the scheme; a flipped byte of the signature or of the digest is
//   invalid_signature.
// - streaming_equals_scheme: for messages of 0, 1, 64 and 1000 bytes, given whole and in pieces
//   of 1 and of 7 bytes, the signer's signature is the scheme's of the message's SHA-512, and each
//   verifies the other's.
// - not_interchangeable: an Ed25519ph signature does not verify under crypto::eddsa, nor an
//   Ed25519 one under crypto::eddsa_prehashed.
// - typed: the scheme's and the signer's results are curves::ed25519::signature; can_sign takes
//   a 64-byte marker alone, and only with an Ed25519 key pair.
// - moved_from: a moved-from key pair signs nothing under the scheme (invalid_state).
// - spent_and_moved: a message is signed or verified once, and a moved-from signer and a
//   moved-from key pair are refused with invalid_state.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;

namespace {

using digest_bytes = std::array<std::uint8_t, 64>;
using signer = ed25519::prehashed_signer<webcpp::hash::sha2_512>;

// RFC 8032 section 7.3, TEST abc.
constexpr char const* secret_key_hex =
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
constexpr char const* public_key_hex =
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
// clang-format off
constexpr char const* signature_hex = "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";
// clang-format on

/** SHA-512 of a message, the digest Ed25519ph signs. */
boost::hash2::digest<64> sha512(std::span<std::uint8_t const> message) {
    webcpp::hash::sha2_512 hasher;
    hasher.update(message.data(), message.size());
    return hasher.result();
}

/** RFC 8032 section 7.3's key pair. */
ed25519::keypair rfc_key() {
    return ed25519::keypair::from_secret(test::from_hex(secret_key_hex)).value();
}

/** RFC 8032 section 7.3's public key. */
ed25519::public_key rfc_public_key() {
    return ed25519::public_key::from_bytes(test::from_hex(public_key_hex)).value();
}

/** RFC 8032 section 7.3's signature. */
ed25519::signature rfc_signature() {
    return ed25519::signature::from_bytes(test::from_hex(signature_hex)).value();
}

/** The message in the pieces given, signed or verified by a signer begun for it. */
signer begun(std::vector<std::vector<std::uint8_t>> const& pieces) {
    auto started = signer::begin();
    BOOST_TEST(started.has_value());
    for (auto const& piece : pieces) {
        BOOST_TEST(started->update(piece).has_value());
    }
    return std::move(*started);
}

void rfc8032_ph() {
    auto const key = ed25519::keypair::from_secret(test::from_hex(secret_key_hex));
    BOOST_TEST(key.has_value());
    if (!key) {
        return;
    }
    auto const key_bytes = test::from_hex(public_key_hex);
    auto const made_key = ed25519::public_key::from_bytes(key_bytes);
    if (!BOOST_TEST(made_key.has_value())) {
        return;
    }
    auto const& public_key = *made_key;
    auto const expected_bytes = test::from_hex(signature_hex);
    auto const made_signature = ed25519::signature::from_bytes(expected_bytes);
    if (!BOOST_TEST(made_signature.has_value())) {
        return;
    }
    auto const& expected = *made_signature;
    std::vector<std::uint8_t> const abc{0x61, 0x62, 0x63};
    std::vector<std::vector<std::uint8_t>> const one_piece{abc};
    std::vector<std::vector<std::uint8_t>> const two_pieces{{0x61}, {0x62, 0x63}};
    std::vector<std::vector<std::uint8_t>> const with_empty{{}, {0x61, 0x62}, {}, {0x63}};
    for (auto const& pieces : {one_piece, two_pieces, with_empty}) {
        auto signing = begun(pieces);
        auto const signature = signing.sign(*key);
        BOOST_TEST(signature && *signature == expected);
        auto verifying = begun(pieces);
        BOOST_TEST(verifying.verify(expected, public_key).has_value());
    }

    // Changed in one bit, the signature is refused; so is another message.
    auto changed = expected_bytes;
    changed[40] ^= 0x01U;
    auto verifying = begun(two_pieces);
    BOOST_TEST(
        verifying.verify(ed25519::signature::from_bytes(changed).value(), public_key).error() ==
        crypto::error::invalid_signature);
    auto other = begun({{0x61, 0x62}});
    BOOST_TEST(other.verify(expected, public_key).error() == crypto::error::invalid_signature);

    // Ed25519ph's signature is not Ed25519's of the same message.
    BOOST_TEST(crypto::verify(crypto::eddsa, expected, abc, public_key).error() ==
               crypto::error::invalid_signature);

    // The arguments in the other order, (public_key, signature): the key's 32 bytes are no
    // signature, refused by from_bytes (bytes where the signature goes do not compile); the
    // signature's bytes are no key.
    BOOST_TEST(ed25519::signature::from_bytes(key_bytes).error() ==
               crypto::error::invalid_signature);
    static_assert(!std::is_convertible_v<std::vector<std::uint8_t>, ed25519::public_key>);

    // A signature of another size, and a key of another size, are never made.
    BOOST_TEST(ed25519::public_key::from_bytes(std::span(key_bytes).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(ed25519::signature::from_bytes(std::span(expected_bytes).first(63)).error() ==
               crypto::error::invalid_signature);
}

void spent_and_moved() {
    auto key = ed25519::keypair::from_secret(test::from_hex(secret_key_hex));
    BOOST_TEST(key.has_value());
    if (!key) {
        return;
    }
    std::vector<std::uint8_t> const abc{0x61, 0x62, 0x63};

    // A message is signed once: the signer is then spent until begun again.
    auto signing = begun({abc});
    BOOST_TEST(signing.sign(*key).has_value());
    BOOST_TEST(signing.update(abc).error() == crypto::error::invalid_state);
    BOOST_TEST(signing.sign(*key).error() == crypto::error::invalid_state);
    auto const public_key = ed25519::public_key::from_bytes(test::from_hex(public_key_hex));
    BOOST_TEST(public_key &&
               signing.verify(ed25519::signature::from_bytes(test::from_hex(signature_hex)).value(),
                              *public_key)
                       .error() == crypto::error::invalid_state);

    // Moved, the target carries the message on; the source is spent.
    auto first = begun({{0x61}});
    signer second = std::move(first);
    // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state
    // is what is tested
    BOOST_TEST(first.update(abc).error() == crypto::error::invalid_state);
    // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
    BOOST_TEST(second.update(std::vector<std::uint8_t>{0x62, 0x63}).has_value());
    auto third = begun({});
    third = std::move(second);
    auto const signature = third.sign(*key);
    BOOST_TEST(signature && std::ranges::equal(signature->bytes(), test::from_hex(signature_hex)));

    // A moved-from key pair signs nothing, and the message stays to be signed.
    ed25519::keypair const taken = std::move(*key);
    auto fourth = begun({abc});
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
    BOOST_TEST(fourth.sign(*key).error() == crypto::error::invalid_state);
    auto const after = fourth.sign(taken);
    BOOST_TEST(after && std::ranges::equal(after->bytes(), test::from_hex(signature_hex)));
}

void rfc8032_ph_scheme() {
    auto const key = rfc_key();
    auto const public_key = rfc_public_key();
    auto const expected = rfc_signature();
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    auto const digest = sha512(abc);
    crypto::prehashed const marker{digest};

    auto const signature = key.sign(crypto::eddsa_prehashed, marker);
    BOOST_TEST(signature && *signature == expected);
    auto const signed_free = crypto::sign(key, crypto::eddsa_prehashed, marker);
    BOOST_TEST(signed_free && *signed_free == expected);
    BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, expected, marker, public_key).has_value());
    BOOST_TEST(public_key.verify(crypto::eddsa_prehashed, expected, marker).has_value());
    BOOST_TEST(crypto::verify<crypto::backends::sodium>(crypto::eddsa_prehashed, expected, marker,
                                                        public_key, ed25519::strict)
                   .has_value());
    BOOST_TEST(public_key
                   .verify<crypto::backends::sodium>(crypto::eddsa_prehashed, expected, marker,
                                                     ed25519::strict)
                   .has_value());

    // A flipped byte of the signature, and of the digest, are refused.
    auto changed_signature = test::from_hex(signature_hex);
    changed_signature[5] ^= 0x01U;
    auto const changed = ed25519::signature::from_bytes(changed_signature).value();
    BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, changed, marker, public_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(public_key.verify(crypto::eddsa_prehashed, changed, marker).error() ==
               crypto::error::invalid_signature);
    auto changed_digest = digest;
    changed_digest[0] ^= 0x01U;
    BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, expected, crypto::prehashed{changed_digest},
                              public_key)
                   .error() == crypto::error::invalid_signature);
    BOOST_TEST(
        public_key.verify(crypto::eddsa_prehashed, expected, crypto::prehashed{changed_digest})
            .error() == crypto::error::invalid_signature);
}

/** The message in pieces of `piece_size` bytes, the last one shorter. */
std::vector<std::vector<std::uint8_t>> pieces_of(std::vector<std::uint8_t> const& message,
                                                 std::size_t piece_size) {
    std::vector<std::vector<std::uint8_t>> pieces;
    for (std::size_t offset = 0; offset < message.size(); offset += piece_size) {
        auto const end = std::min(message.size(), offset + piece_size);
        pieces.emplace_back(message.begin() + static_cast<std::ptrdiff_t>(offset),
                            message.begin() + static_cast<std::ptrdiff_t>(end));
    }
    return pieces;
}

void streaming_equals_scheme() {
    auto const key = rfc_key();
    auto const public_key = rfc_public_key();
    for (std::size_t const size :
         {std::size_t{0}, std::size_t{1}, std::size_t{64}, std::size_t{1000}}) {
        std::vector<std::uint8_t> message(size);
        for (std::size_t index = 0; index < size; ++index) {
            message[index] = static_cast<std::uint8_t>((index * 31U) + 7U);
        }
        auto const digest = sha512(message);
        auto const scheme_signature = key.sign(crypto::eddsa_prehashed, crypto::prehashed{digest});
        if (!BOOST_TEST(scheme_signature.has_value())) {
            continue;
        }
        std::vector<std::vector<std::vector<std::uint8_t>>> const cuts{
            {message},
            pieces_of(message, 1),
            pieces_of(message, 7),
        };
        for (auto const& pieces : cuts) {
            auto signing = begun(pieces);
            auto const streamed = signing.sign(key);
            BOOST_TEST(streamed && *streamed == *scheme_signature);
            auto verifying = begun(pieces);
            BOOST_TEST(verifying.verify(*scheme_signature, public_key).has_value());
            if (streamed) {
                BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, *streamed,
                                          crypto::prehashed{digest}, public_key)
                               .has_value());
            }
        }
    }
}

void not_interchangeable() {
    auto const key = rfc_key();
    auto const public_key = rfc_public_key();
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    auto const prehashed_signature_value =
        key.sign(crypto::eddsa_prehashed, crypto::prehashed{sha512(abc)}).value();
    BOOST_TEST(crypto::verify(crypto::eddsa, prehashed_signature_value, abc, public_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::eddsa_prehashed, key.sign(crypto::eddsa, abc).value(),
                              crypto::prehashed{sha512(abc)}, public_key)
                   .error() == crypto::error::invalid_signature);
}

void typed() {
    auto const key = rfc_key();
    std::array<std::uint8_t, 64> const digest{};
    crypto::prehashed const marker{digest};
    static_assert(std::is_same_v<decltype(key.sign(crypto::eddsa_prehashed, marker)),
                                 boost::system::result<ed25519::signature>>);
    static_assert(std::is_same_v<decltype(std::declval<signer&>().sign(key)),
                                 boost::system::result<ed25519::signature>>);
    static_assert(
        std::is_same_v<crypto::detail::signature_of_t<ed25519::keypair, crypto::eddsa_prehashed_t>,
                       ed25519::signature>);
    static_assert(std::is_same_v<
                  crypto::detail::signature_of_t<ed25519::public_key, crypto::eddsa_prehashed_t>,
                  ed25519::signature>);
    static_assert(
        crypto::can_sign<ed25519::keypair, crypto::eddsa_prehashed_t, crypto::prehashed<64>>);
    static_assert(!crypto::can_sign<ed25519::keypair, crypto::eddsa_prehashed_t,
                                    std::span<std::uint8_t const>>);
    static_assert(!crypto::can_sign<ed25519::keypair, crypto::eddsa_prehashed_t, digest_bytes>);
    static_assert(
        !crypto::can_sign<ed25519::keypair, crypto::eddsa_prehashed_t, crypto::prehashed<32>>);
    static_assert(!crypto::can_sign<crypto::curves::p256::keypair, crypto::eddsa_prehashed_t,
                                    crypto::prehashed<64>>);
    static_assert(!crypto::can_sign<crypto::curves::secp256k1::keypair, crypto::eddsa_prehashed_t,
                                    crypto::prehashed<64>>);
    static_assert(crypto::can_verify<crypto::eddsa_prehashed_t, ed25519::signature,
                                     crypto::prehashed<64>, ed25519::public_key>);
    static_assert(!crypto::can_verify<crypto::eddsa_prehashed_t, ed25519::signature, digest_bytes,
                                      ed25519::public_key>);
    static_assert(crypto::detail::has_verifier_v<crypto::eddsa_prehashed_t, ed25519::public_key>);
    // eddsa still takes no marker.
    static_assert(!crypto::can_sign<ed25519::keypair, crypto::eddsa_t, crypto::prehashed<64>>);
    BOOST_TEST(key.sign(crypto::eddsa_prehashed, marker).has_value());
}

void moved_from() {
    auto key = rfc_key();
    ed25519::keypair const taken = std::move(key);
    std::array<std::uint8_t, 64> const digest{};
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
    BOOST_TEST(key.sign(crypto::eddsa_prehashed, crypto::prehashed{digest}).error() ==
               crypto::error::invalid_state);
    BOOST_TEST(taken.sign(crypto::eddsa_prehashed, crypto::prehashed{digest}).has_value());
}

}  // namespace

int main() {
    static_assert(
        std::is_same_v<
            signer, ed25519::prehashed_signer<webcpp::hash::sha2_512, crypto::backends::sodium>>);
    static_assert(std::is_same_v<signer::family_type, crypto::families::ed25519>);
    static_assert(std::is_same_v<signer::name_type, crypto::tags::ed25519ph>);
    static_assert(!std::is_copy_constructible_v<signer> && !std::is_copy_assignable_v<signer>);
    static_assert(std::is_nothrow_move_constructible_v<signer> &&
                  std::is_nothrow_move_assignable_v<signer>);
    rfc8032_ph();
    rfc8032_ph_scheme();
    streaming_equals_scheme();
    not_interchangeable();
    typed();
    moved_from();
    spent_and_moved();
    return test::exit_status(boost::report_errors());
}
