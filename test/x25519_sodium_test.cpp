// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// X25519 on libsodium: RFC 7748 section 5.2's two scalar multiplications and section 6.1's
// Alice and Bob; a peer key of order 8 (Wycheproof's tcId 63) refused with weak_public_key; the
// guards (keys of other sizes); detail::is_all_zero; and the conversion from Ed25519: the X25519
// public key of a key pair's x25519_secret() equals curves::ed25519::to_x25519_public of its
// Ed25519 public key, and an Ed25519 key of small order, not canonical or off the curve is
// invalid_public_key.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/supports.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <type_traits>
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

/** RFC 7748 section 5.2: an input scalar and u-coordinate, and the output u-coordinate. */
void scalar_multiplication(std::string_view scalar, std::string_view u, std::string_view out) {
    auto const shared = x25519::agree(test::from_hex(scalar), test::from_hex(u));
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

void rfc7748_section_6_1() {
    auto const alice_secret =
        test::from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto const bob_secret =
        test::from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    auto const alice_public = x25519::public_key(alice_secret);
    auto const bob_public = x25519::public_key(bob_secret);
    BOOST_TEST(alice_public.has_value());
    BOOST_TEST(bob_public.has_value());
    if (!alice_public || !bob_public) {
        return;
    }
    BOOST_TEST(bytes_of(*alice_public) ==
               test::from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    BOOST_TEST(bytes_of(*bob_public) ==
               test::from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    auto const shared =
        test::from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    auto const alice_shared = x25519::agree(alice_secret, *bob_public);
    auto const bob_shared =
        x25519::algorithm<crypto::backends::sodium>::agree(bob_secret, *alice_public);
    BOOST_TEST(alice_shared.has_value());
    BOOST_TEST(bob_shared.has_value());
    if (alice_shared && bob_shared) {
        BOOST_TEST(bytes_of(*alice_shared) == shared);
        BOOST_TEST(bytes_of(*bob_shared) == shared);
    }
}

void weak_peer() {
    // Wycheproof x25519_test.json, tcId 63: a public key of order 8, whose shared secret is 0.
    auto const shared = x25519::agree(
        test::from_hex("e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272"),
        test::from_hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"));
    BOOST_TEST(!shared.has_value());
    BOOST_TEST(shared.error() == crypto::error::weak_public_key);
}

void guards() {
    std::array<std::uint8_t, 33> const long_key{};
    std::array<std::uint8_t, 32> const key{9};
    BOOST_TEST(x25519::public_key(std::span(long_key).first(31)).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(x25519::public_key(long_key).error() == crypto::error::invalid_key_size);
    BOOST_TEST(x25519::agree(std::span(long_key).first(31), key).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(x25519::agree(key, std::span(long_key).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(x25519::agree(key, long_key).error() == crypto::error::invalid_public_key);
    BOOST_TEST(ed25519::to_x25519_public(std::span(long_key).first(31)).error() ==
               crypto::error::invalid_public_key);
    BOOST_TEST(ed25519::to_x25519_public(long_key).error() == crypto::error::invalid_public_key);
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
    auto const key = ed25519::keypair::make(test::from_hex(seed));
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
    auto const derived = x25519::public_key(secret_key->bytes());
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
        // A point of order 4, (0, -1).
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // The neutral element written with y = p + 1, not canonical.
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        // y = 2, whose x is not on the curve.
        "0200000000000000000000000000000000000000000000000000000000000000",
    });
    for (auto const key : refused) {
        auto const converted = ed25519::to_x25519_public(test::from_hex(key));
        BOOST_TEST(!converted.has_value());
        if (!converted) {
            BOOST_TEST(converted.error() == crypto::error::invalid_public_key);
        }
    }
}

// The algorithm names its family, its name and its backend, as the capability table does.
static_assert(std::is_same_v<x25519::algorithm<>::family_type, crypto::families::x25519>);
static_assert(std::is_same_v<x25519::algorithm<>::name_type, crypto::families::x25519>);
static_assert(std::is_same_v<x25519::algorithm<>::backend_type, crypto::backends::sodium>);
static_assert(x25519::algorithm<>::key_size == 32);
static_assert(crypto::supports_v<x25519::algorithm<>, crypto::backends::sodium>);

}  // namespace

int main() {
    rfc7748_section_5_2();
    rfc7748_section_6_1();
    weak_peer();
    guards();
    all_zero();
    conversion();
    conversion_refuses();
    return test::exit_status(boost::report_errors());
}
