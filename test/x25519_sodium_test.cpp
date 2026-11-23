// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// X25519 on libsodium, on typed keys:
// - rfc7748_section_5_2: section 5.2's two scalar multiplications, the scalar a key pair's secret
//   key and the u-coordinate a public key made by from_bytes.
// - rfc7748: section 6.1's Alice and Bob, made with from_secret, give the RFC's public keys and
//   agree in both directions on the RFC's shared secret, through the member, the free
//   crypto::agree, the free crypto::from_secret and the backend named; detail::x25519_access views
//   the key pair's own bytes.
// - secret_round_trip: from_secret of a key pair's secret() has its public key.
// - sizes: from_bytes of 31 and 33 bytes is invalid_public_key, from_secret of 31 and 33 bytes
//   invalid_key_size.
// - weak_peer: a peer key of order 8 (Wycheproof's tcId 63) and one of 32 zero bytes are refused
//   by agree with weak_public_key.
// - moved_from: a key pair moved from, by construction and by assignment, refuses public_key,
//   secret and agree with invalid_state, and the one moved to agrees as the source did.
// - generated: two generated key pairs differ and agree with each other.
// - all_zero: detail::is_all_zero.
// - conversion: the X25519 public key of an Ed25519 key pair's x25519_secret() equals
//   curves::ed25519::to_x25519_public of its Ed25519 public key, and an Ed25519 key of small
//   order, of mixed order, not canonical or off the curve is invalid_public_key.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;

namespace {

/** The bytes of a secret, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(crypto::secret<32> const& shared) {
    auto const view = shared.bytes();
    return {view.begin(), view.end()};
}

/** The bytes of a public key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(std::array<std::uint8_t, 32> const& key) {
    return {key.begin(), key.end()};
}

/** The bytes of a typed public key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(x25519::public_key const& key) {
    return bytes_of(key.bytes());
}

constexpr std::string_view alice_secret_hex =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view alice_public_hex =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
constexpr std::string_view bob_secret_hex =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr std::string_view bob_public_hex =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
constexpr std::string_view shared_hex =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/** RFC 7748 section 5.2: an input scalar and u-coordinate, and the output u-coordinate. */
void scalar_multiplication(std::string_view scalar, std::string_view u, std::string_view out) {
    auto const key = x25519::keypair::from_secret(test::from_hex(scalar));
    auto const peer = x25519::public_key::from_bytes(test::from_hex(u));
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    auto const shared = key->agree(*peer);
    BOOST_TEST(shared.has_value());
    if (shared) {
        BOOST_TEST(bytes_of(*shared) == test::from_hex(out));
    }
}

void rfc7748_section_5_2() {
    scalar_multiplication("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    scalar_multiplication("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                          "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

void rfc7748() {
    auto const alice = x25519::keypair::from_secret(test::from_hex(alice_secret_hex));
    auto const bob = x25519::basic_keypair<crypto::backends::sodium>::from_secret(
        test::from_hex(bob_secret_hex));
    if (!BOOST_TEST(alice.has_value()) || !BOOST_TEST(bob.has_value())) {
        return;
    }
    auto const alice_public = alice->public_key();
    auto const bob_public = bob->public_key();
    if (!BOOST_TEST(alice_public.has_value()) || !BOOST_TEST(bob_public.has_value())) {
        return;
    }
    BOOST_TEST(bytes_of(*alice_public) == test::from_hex(alice_public_hex));
    BOOST_TEST(bytes_of(*bob_public) == test::from_hex(bob_public_hex));
    auto const shared = test::from_hex(shared_hex);
    auto const alice_shared = alice->agree(*bob_public);
    auto const bob_shared = bob->agree(*alice_public);
    BOOST_TEST(alice_shared.has_value() && bytes_of(*alice_shared) == shared);
    BOOST_TEST(bob_shared.has_value() && bytes_of(*bob_shared) == shared);

    // The free forms equal the members.
    auto const free_shared = crypto::agree(*alice, *bob_public);
    BOOST_TEST(free_shared.has_value() && bytes_of(*free_shared) == shared);
    auto const free_made = crypto::from_secret<x25519::keypair>(test::from_hex(alice_secret_hex));
    BOOST_TEST(free_made.has_value() && free_made->public_key() == alice_public);

    // The access the boxes and crypto_kx use views the key pair's own bytes.
    auto const secret_key = alice->secret();
    BOOST_TEST(secret_key.has_value() &&
               std::ranges::equal(crypto::detail::x25519_access::secret_bytes(*alice),
                                  secret_key->bytes()));
    BOOST_TEST(std::ranges::equal(crypto::detail::x25519_access::public_bytes(*alice),
                                  alice_public->bytes()));
}

void secret_round_trip() {
    auto const key = x25519::keypair::from_secret(test::from_hex(alice_secret_hex));
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const secret_key = key->secret();
    if (!BOOST_TEST(secret_key.has_value())) {
        return;
    }
    BOOST_TEST(bytes_of(*secret_key) == test::from_hex(alice_secret_hex));
    auto const again = x25519::keypair::from_secret(secret_key->bytes());
    BOOST_TEST(again.has_value() && again->public_key() == key->public_key());
}

void sizes() {
    std::array<std::uint8_t, 33> const long_key{9};
    BOOST_TEST(x25519::public_key::from_bytes(std::span(long_key).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(x25519::public_key::from_bytes(long_key).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(crypto::from_bytes<x25519::public_key>(long_key).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(x25519::public_key::from_bytes(std::span(long_key).first(32)).has_value());
    BOOST_TEST(x25519::keypair::from_secret(std::span(long_key).first(31)).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(x25519::keypair::from_secret(long_key).error() == crypto::error::invalid_key_size);
    // An Ed25519 key of another size is never made, so to_x25519_public never sees one.
    BOOST_TEST(ed25519::public_key::from_bytes(std::span(long_key).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(ed25519::public_key::from_bytes(long_key).error() ==
               crypto::error::invalid_public_key);
}

/** A key pair's agreement with a peer key's bytes, refused with weak_public_key. */
void refused_as_weak(x25519::keypair const& key, std::span<std::uint8_t const> peer_bytes) {
    auto const peer = x25519::public_key::from_bytes(peer_bytes);
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    auto const shared = key.agree(*peer);
    BOOST_TEST(!shared.has_value());
    if (!shared) {
        BOOST_TEST(shared.error() == crypto::error::weak_public_key);
    }
}

void weak_peer() {
    // Wycheproof x25519_test.json, tcId 63: a public key of order 8, whose shared secret is 0.
    auto const key = x25519::keypair::from_secret(
        test::from_hex("e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272"));
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    refused_as_weak(
        *key, test::from_hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"));
    std::array<std::uint8_t, 32> const zero_point{};
    refused_as_weak(*key, zero_point);
}

/** Whether a key pair refuses its three members with invalid_state. */
void refuses_every_member(x25519::keypair const& key, x25519::public_key const& peer) {
    BOOST_TEST(key.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(key.secret().error() == crypto::error::invalid_state);
    BOOST_TEST(key.agree(peer).error() == crypto::error::invalid_state);
}

void moved_from() {
    auto made = x25519::keypair::from_secret(test::from_hex(alice_secret_hex));
    auto other = x25519::keypair::from_secret(test::from_hex(bob_secret_hex));
    auto const peer = x25519::public_key::from_bytes(test::from_hex(bob_public_hex));
    if (!BOOST_TEST(made.has_value()) || !BOOST_TEST(other.has_value()) ||
        !BOOST_TEST(peer.has_value())) {
        return;
    }
    x25519::keypair taken(std::move(*made));
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
    refuses_every_member(*made, *peer);
    auto const shared = taken.agree(*peer);
    BOOST_TEST(shared.has_value() && bytes_of(*shared) == test::from_hex(shared_hex));
    taken = std::move(*other);
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair's refusal
    refuses_every_member(*other, *peer);
    auto const own = taken.public_key();
    BOOST_TEST(own.has_value() && bytes_of(*own) == test::from_hex(bob_public_hex));
}

void generated() {
    auto const first = x25519::keypair::generate();
    auto const second = crypto::generate<x25519::keypair>();
    if (!BOOST_TEST(first.has_value()) || !BOOST_TEST(second.has_value())) {
        return;
    }
    auto const first_public = first->public_key();
    auto const second_public = second->public_key();
    if (!BOOST_TEST(first_public.has_value()) || !BOOST_TEST(second_public.has_value())) {
        return;
    }
    BOOST_TEST(!(*first_public == *second_public));
    auto const first_shared = first->agree(*second_public);
    auto const second_shared = second->agree(*first_public);
    BOOST_TEST(first_shared.has_value() && second_shared.has_value() &&
               bytes_of(*first_shared) == bytes_of(*second_shared));
}

void all_zero() {
    std::array<std::uint8_t, 32> bytes{};
    BOOST_TEST(crypto::detail::is_all_zero(bytes));
    BOOST_TEST(crypto::detail::is_all_zero(std::span<std::uint8_t const>{}));
    bytes.back() = 0x80;
    BOOST_TEST(!crypto::detail::is_all_zero(bytes));
    bytes.back() = 0;
    bytes.front() = 1;
    BOOST_TEST(!crypto::detail::is_all_zero(bytes));
}

/** One Ed25519 key pair's X25519 public key, derived from its secret and converted. */
void converted(std::string_view seed) {
    auto const key = ed25519::keypair::from_secret(test::from_hex(seed));
    BOOST_TEST(key.has_value());
    if (!key) {
        return;
    }
    auto const secret_key = key->x25519_secret();
    auto const ed25519_public = key->public_key();
    BOOST_TEST(secret_key.has_value());
    BOOST_TEST(ed25519_public.has_value());
    if (!secret_key || !ed25519_public) {
        return;
    }
    auto const x25519_key = x25519::keypair::from_secret(secret_key->bytes());
    if (!BOOST_TEST(x25519_key.has_value())) {
        return;
    }
    auto const derived = x25519_key->public_key();
    auto const converted_key = ed25519::to_x25519_public(*ed25519_public);
    auto const named = ed25519::to_x25519_public<crypto::backends::sodium>(*ed25519_public);
    BOOST_TEST(derived.has_value());
    BOOST_TEST(converted_key.has_value());
    BOOST_TEST(named.has_value());
    if (derived && converted_key && named) {
        BOOST_TEST(bytes_of(*derived) == bytes_of(*converted_key));
        BOOST_TEST(bytes_of(*named) == bytes_of(*converted_key));
    }
}

void conversion() {
    // RFC 8032 section 7.1's secret keys (seeds): the X25519 key pair of an Ed25519 key pair.
    constexpr auto seeds = std::to_array<std::string_view>({
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    });
    for (auto const seed : seeds) {
        converted(seed);
    }
}

void conversion_refuses() {
    constexpr auto refused = std::to_array<std::string_view>({
        // The neutral element, of order 1.
        "0100000000000000000000000000000000000000000000000000000000000000",
        // A point of order 8.
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        // A point of order 2, (0, -1).
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // The neutral element written with y = p + 1, not canonical.
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // y = 2, whose x is not on the curve.
        "0200000000000000000000000000000000000000000000000000000000000000",
        // A point of mixed order 8L: RFC 8032 section 7.1's first public key plus the point of
        // order 8 above. Not of small order and on the curve: refused only as outside the
        // prime-order subgroup.
        "9158312a9a8d6e3b34c891d6d61444f8b8211c5117ebad15bdb0bd68b07e0245",
        // y = p + 3, not canonical: on the curve, of order 8L, so refused only as outside the
        // prime-order subgroup.
        "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    });
    for (auto const key : refused) {
        // Made, since the size is right: the conversion judges the point.
        auto const made = ed25519::public_key::from_bytes(test::from_hex(key));
        if (!BOOST_TEST(made.has_value())) {
            continue;
        }
        auto const converted = ed25519::to_x25519_public(*made);
        BOOST_TEST(!converted.has_value());
        if (!converted) {
            BOOST_TEST(converted.error() == crypto::error::invalid_public_key);
        }
    }
}

// The key pair names its family, its name and its backend, as the capability table does.
static_assert(std::is_same_v<x25519::keypair::family_type, crypto::families::x25519>);
static_assert(std::is_same_v<x25519::keypair::name_type, crypto::families::x25519>);
static_assert(std::is_same_v<x25519::keypair::backend_type, crypto::backends::sodium>);
static_assert(std::is_same_v<x25519::keypair::public_key_type, x25519::public_key>);
static_assert(x25519::keypair::secret_key_size == 32);
static_assert(x25519::public_key::public_key_size == 32);
static_assert(crypto::supports_v<x25519::keypair, crypto::backends::sodium>);
// The public key is made by from_bytes and a key pair alone; the key pair is not copied.
static_assert(!std::is_default_constructible_v<x25519::public_key>);
static_assert(!std::is_default_constructible_v<x25519::keypair>);
static_assert(!std::is_copy_constructible_v<x25519::keypair>);
static_assert(std::is_nothrow_move_constructible_v<x25519::keypair>);
static_assert(std::is_nothrow_move_assignable_v<x25519::keypair>);

}  // namespace

int main() {
    rfc7748_section_5_2();
    rfc7748();
    secret_round_trip();
    sizes();
    weak_peer();
    moved_from();
    generated();
    all_zero();
    conversion();
    conversion_refuses();
    return test::exit_status(boost::report_errors());
}
