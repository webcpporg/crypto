// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's parsed public key in both SEC1 forms: the generator's first multiples parse and
// serialise, compressed and uncompressed, and a key pair's two forms parse to one key; every
// length but 33 and 65, every prefix but 02, 03 and 04 (X9.62's hybrid 06 and 07 with a valid
// point, which libsecp256k1 alone takes, among them), an x not below the field's prime and an
// x with no y are invalid_public_key; keys order as their compressed bytes.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;

namespace {

static_assert(!std::is_default_constructible_v<secp::public_key>);
static_assert(std::is_trivially_copyable_v<secp::public_key>);
static_assert(secp::point_size<secp::point_form::compressed> == 33);
static_assert(secp::point_size<secp::point_form::uncompressed> == 65);
static_assert(
    std::is_same_v<decltype(secp::serialize_public_key(std::declval<secp::public_key const&>())),
                   std::array<std::uint8_t, 33>>);
static_assert(std::is_same_v<decltype(secp::serialize_public_key<secp::point_form::uncompressed>(
                                 std::declval<secp::public_key const&>())),
                             std::array<std::uint8_t, 65>>);

// The compressed keys of 1G, 2G and 3G: the public keys of the secrets 1, 2 and 3.
constexpr std::array<std::string_view, 3> multiples = {
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
};

// The secret key k, 32 bytes big-endian.
std::array<std::uint8_t, 32> small_secret(std::uint8_t k) {
    std::array<std::uint8_t, 32> secret{};
    secret.back() = k;
    return secret;
}

void refused(std::string const& label, std::span<std::uint8_t const> encoded) {
    auto const parsed = secp::parse_public_key(encoded);
    if (!BOOST_TEST(parsed.has_error()) ||
        !BOOST_TEST(parsed.error() == crypto::error::invalid_public_key)) {
        BOOST_ERROR(label.c_str());
    }
}

// 1G, 2G and 3G: each is the key pair's of its secret, parses, serialises to its bytes, and
// comes back to them through the uncompressed form.
void generator_multiples() {
    for (std::size_t i = 0; i < multiples.size(); ++i) {
        auto const expected = test::from_hex(multiples[i]);
        auto const key = secp::keypair::make(small_secret(static_cast<std::uint8_t>(i + 1)));
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        auto const from_pair = key->public_key();
        BOOST_TEST(from_pair && std::ranges::equal(*from_pair, expected));
        auto const parsed = secp::parse_public_key(expected);
        if (!BOOST_TEST(parsed.has_value())) {
            continue;
        }
        auto const compressed = secp::serialize_public_key(*parsed);
        BOOST_TEST(std::ranges::equal(compressed, expected));
        auto const uncompressed =
            secp::serialize_public_key<secp::point_form::uncompressed>(*parsed);
        BOOST_TEST_EQ(uncompressed[0], 0x04);
        BOOST_TEST(std::ranges::equal(std::span(uncompressed).subspan(1, 32),
                                      std::span(expected).subspan(1, 32)));
        auto const again = secp::parse_public_key(uncompressed);
        if (BOOST_TEST(again.has_value())) {
            BOOST_TEST(*again == *parsed);
            BOOST_TEST(std::ranges::equal(secp::serialize_public_key(*again), expected));
            BOOST_TEST(std::ranges::equal(
                secp::serialize_public_key<secp::point_form::uncompressed>(*again), uncompressed));
        }
    }
}

// A key pair's uncompressed key parses to the same key as its compressed one.
void keypair_forms() {
    for (std::uint8_t k = 1; k <= 16; ++k) {
        auto const key = secp::keypair::make(small_secret(k));
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        auto const compressed = key->public_key();
        auto const uncompressed = key->public_key_uncompressed();
        if (!BOOST_TEST(compressed && uncompressed)) {
            continue;
        }
        BOOST_TEST_EQ((*uncompressed)[0], 0x04);
        auto const from_compressed = secp::parse_public_key(*compressed);
        auto const from_uncompressed = secp::parse_public_key(*uncompressed);
        if (BOOST_TEST(from_compressed && from_uncompressed)) {
            BOOST_TEST(*from_compressed == *from_uncompressed);
            BOOST_TEST(std::ranges::equal(
                secp::serialize_public_key<secp::point_form::uncompressed>(*from_compressed),
                *uncompressed));
        }
    }
}

// The SEC1 uncompressed form of a compressed key, through libsecp256k1.
std::array<std::uint8_t, 65> uncompressed_of(std::span<std::uint8_t const> compressed) {
    secp256k1_pubkey point{};
    BOOST_TEST_EQ(secp256k1_ec_pubkey_parse(secp256k1_context_static, &point, compressed.data(),
                                            compressed.size()),
                  1);
    std::array<std::uint8_t, 65> out{};
    std::size_t size = out.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_UNCOMPRESSED;
    BOOST_TEST_EQ(
        secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &size, &point, flags),
        1);
    return out;
}

// Whether libsecp256k1's own parser takes the bytes.
bool libsecp256k1_takes(std::span<std::uint8_t const> encoded) {
    secp256k1_pubkey point{};
    return secp256k1_ec_pubkey_parse(secp256k1_context_static, &point, encoded.data(),
                                     encoded.size()) == 1;
}

void refusals() {
    auto const one_g = test::from_hex(multiples[0]);
    auto const one_g_long = uncompressed_of(one_g);

    // Every length but 33 and 65.
    for (std::size_t const size : {0U, 1U, 32U, 34U, 64U, 66U}) {
        std::vector<std::uint8_t> encoded(one_g_long.begin(), one_g_long.end());
        encoded.resize(size, 0x01);
        refused("length " + std::to_string(size), encoded);
    }

    // Every prefix but 02, 03 and 04, on 33 and on 65 bytes.
    for (std::uint8_t const prefix : {0x00, 0x01, 0x05, 0x06, 0x07, 0x08, 0xff}) {
        auto short_form = one_g;
        short_form[0] = prefix;
        refused("prefix " + std::to_string(prefix) + ", 33 bytes", short_form);
        auto long_form = one_g_long;
        long_form[0] = prefix;
        refused("prefix " + std::to_string(prefix) + ", 65 bytes", long_form);
    }

    // X9.62's hybrid forms of valid points, 06 for an even y (1G) and 07 for an odd one (6G),
    // which libsecp256k1 alone takes.
    auto hybrid_even = one_g_long;
    hybrid_even[0] = 0x06;
    BOOST_TEST(libsecp256k1_takes(hybrid_even));
    refused("hybrid 06, a valid point", hybrid_even);
    auto const six_g =
        test::from_hex("03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556");
    auto hybrid_odd = uncompressed_of(six_g);
    hybrid_odd[0] = 0x07;
    BOOST_TEST(libsecp256k1_takes(hybrid_odd));
    refused("hybrid 07, a valid point", hybrid_odd);

    // An x not below the field's prime p, and p itself.
    auto const p_itself =
        test::from_hex("02fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    refused("x = p", p_itself);
    auto const all_ones =
        test::from_hex("03ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    refused("x = 2^256 - 1", all_ones);
    auto p_long = one_g_long;
    std::ranges::copy(std::span(p_itself).subspan(1), p_long.begin() + 1);
    refused("x = p, 65 bytes", p_long);

    // x = 5: x^3 + 7 is not a square modulo p, so no point has this x. x = 0 neither.
    for (std::uint8_t const x : {0x00, 0x05}) {
        std::array<std::uint8_t, 33> no_y{};
        no_y[0] = 0x02;
        no_y.back() = x;
        BOOST_TEST(!libsecp256k1_takes(no_y));
        refused("x = " + std::to_string(x) + ", no y", no_y);
    }

    // A point whose y is not the curve's for its x.
    auto off_curve = one_g_long;
    off_curve.back() ^= 0x01;
    refused("y off the curve", off_curve);
}

// Keys order as their compressed encodings: 1G, 2G, 3G; a key equals its re-parsed copy.
void ordering() {
    std::vector<secp::public_key> keys;
    for (auto const hex : multiples) {
        auto const parsed = secp::parse_public_key(test::from_hex(hex));
        if (!BOOST_TEST(parsed.has_value())) {
            return;
        }
        keys.push_back(*parsed);
    }
    BOOST_TEST(keys[0] < keys[1]);
    BOOST_TEST(keys[1] < keys[2]);
    BOOST_TEST(keys[0] < keys[2]);
    BOOST_TEST(keys[2] > keys[0]);
    BOOST_TEST((keys[1] <=> keys[1]) == std::strong_ordering::equal);
    BOOST_TEST(keys[0] != keys[1]);
    std::vector<secp::public_key> reversed(keys.rbegin(), keys.rend());
    std::ranges::sort(reversed);
    BOOST_TEST(reversed == keys);
    for (auto const& key : keys) {
        auto const copy = secp::parse_public_key(secp::serialize_public_key(key));
        if (BOOST_TEST(copy.has_value())) {
            BOOST_TEST(*copy == key);
            BOOST_TEST((*copy <=> key) == std::strong_ordering::equal);
        }
    }
    // A key's two forms order alike: the order reads the point, not the bytes it came from.
    auto const long_one =
        secp::parse_public_key(secp::serialize_public_key<secp::point_form::uncompressed>(keys[0]));
    if (BOOST_TEST(long_one.has_value())) {
        BOOST_TEST(*long_one < keys[1]);
        BOOST_TEST(*long_one == keys[0]);
    }
}

}  // namespace

int main() {
    generator_multiples();
    keypair_forms();
    refusals();
    ordering();
    return webcpp::test::exit_status(boost::report_errors());
}
