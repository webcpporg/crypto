// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519ph on libsodium: RFC 8032 section 7.3's test, the message "abc" given in one piece and
// in two, signed into the RFC's signature and verified with verify(signature, public_key), the
// signature first and the key a curves::ed25519::public_key; the key's bytes where the signature
// goes refused as a signature; a signature changed in one bit and a different message refused; a
// message is signed or verified once, and a moved-from signer and a moved-from key pair are refused
// with invalid_state.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;

namespace {

using signer = ed25519::ph<webcpp::hash::sha2_512>;

// RFC 8032 section 7.3, TEST abc.
constexpr char const* secret_key =
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42";
constexpr char const* public_key_hex =
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
// clang-format off
constexpr char const* signature_hex = "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";
// clang-format on

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
    auto const key = ed25519::keypair::from_secret(test::from_hex(secret_key));
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
    auto const expected = test::from_hex(signature_hex);
    std::vector<std::uint8_t> const abc{0x61, 0x62, 0x63};
    std::vector<std::vector<std::uint8_t>> const one_piece{abc};
    std::vector<std::vector<std::uint8_t>> const two_pieces{{0x61}, {0x62, 0x63}};
    std::vector<std::vector<std::uint8_t>> const with_empty{{}, {0x61, 0x62}, {}, {0x63}};
    for (auto const& pieces : {one_piece, two_pieces, with_empty}) {
        auto signing = begun(pieces);
        auto const signature = signing.sign(*key);
        BOOST_TEST(signature && std::ranges::equal(*signature, expected));
        auto verifying = begun(pieces);
        BOOST_TEST(verifying.verify(expected, public_key).has_value());
    }

    // Changed in one bit, the signature is refused; so is another message.
    auto changed = expected;
    changed[40] ^= 0x01U;
    auto verifying = begun(two_pieces);
    BOOST_TEST(verifying.verify(changed, public_key).error() == crypto::error::invalid_signature);
    auto other = begun({{0x61, 0x62}});
    BOOST_TEST(other.verify(expected, public_key).error() == crypto::error::invalid_signature);

    // Ed25519ph's signature is not Ed25519's of the same message.
    BOOST_TEST(crypto::verify(crypto::eddsa, expected, abc, public_key).error() ==
               crypto::error::invalid_signature);

    // The arguments in the other order, (public_key, signature): the key's 32 bytes stand where
    // the signature goes and are refused as a signature; the signature's bytes are no key.
    auto swapped = begun(one_piece);
    BOOST_TEST(swapped.verify(key_bytes, public_key).error() == crypto::error::invalid_signature);
    static_assert(!std::is_convertible_v<std::vector<std::uint8_t>, ed25519::public_key>);

    // A signature of another size; a key of another size is never made.
    BOOST_TEST(ed25519::public_key::from_bytes(std::span(key_bytes).first(31)).error() ==
               crypto::error::invalid_public_key);
    auto short_signature = begun(one_piece);
    BOOST_TEST(short_signature.verify(std::span(expected).first(63), public_key).error() ==
               crypto::error::invalid_signature);
}

void spent_and_moved() {
    auto key = ed25519::keypair::from_secret(test::from_hex(secret_key));
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
    BOOST_TEST(public_key && signing.verify(test::from_hex(signature_hex), *public_key).error() ==
                                 crypto::error::invalid_state);

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
    BOOST_TEST(signature && std::ranges::equal(*signature, test::from_hex(signature_hex)));

    // A moved-from key pair signs nothing, and the message stays to be signed.
    ed25519::keypair const taken = std::move(*key);
    auto fourth = begun({abc});
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): tested
    BOOST_TEST(fourth.sign(*key).error() == crypto::error::invalid_state);
    auto const after = fourth.sign(taken);
    BOOST_TEST(after && std::ranges::equal(*after, test::from_hex(signature_hex)));
}

}  // namespace

int main() {
    static_assert(
        std::is_same_v<signer, ed25519::ph<webcpp::hash::sha2_512, crypto::backends::sodium>>);
    static_assert(std::is_same_v<signer::family_type, crypto::families::ed25519>);
    static_assert(std::is_same_v<signer::name_type, crypto::tags::ed25519ph>);
    static_assert(!std::is_copy_constructible_v<signer> && !std::is_copy_assignable_v<signer>);
    static_assert(std::is_nothrow_move_constructible_v<signer> &&
                  std::is_nothrow_move_assignable_v<signer>);
    rfc8032_ph();
    spent_and_moved();
    return test::exit_status(boost::report_errors());
}
