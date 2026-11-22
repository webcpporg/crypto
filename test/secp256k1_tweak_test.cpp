// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's tweaks, negation and combination of secret and public keys. Over 64 seeded
// secrets d and tweaks t, with P(x) the public key of the secret x: P(d) + tG is
// P(d + t), tP(d) is P(dt), -P(d) is P(-d), -(-d) is d, P(d) + P(t) is P(d + t), and each
// result equals libsecp256k1's C API called directly. The known answer 1 + 1, whose public key
// is 2G. The refusals: a tweak equal to the group order, a sum or a product that is zero, a
// zero or order-sized secret, a sum of keys at infinity, no keys and a short workspace. The
// workspace is zero after every call, one that starts off the alignment included.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;

namespace {

using scalar = std::array<std::uint8_t, 32>;

constexpr std::string_view order_hex =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

static_assert(std::is_same_v<decltype(secp::seckey_tweak_add(std::declval<scalar const&>(),
                                                             std::declval<scalar const&>())),
                             boost::system::result<crypto::secret<32>>>);
static_assert(std::is_same_v<decltype(secp::seckey_tweak_mul(std::declval<scalar const&>(),
                                                             std::declval<scalar const&>())),
                             boost::system::result<crypto::secret<32>>>);
static_assert(std::is_same_v<decltype(secp::seckey_negate(std::declval<scalar const&>())),
                             boost::system::result<crypto::secret<32>>>);
static_assert(
    std::is_same_v<decltype(secp::pubkey_tweak_add(std::declval<secp::public_key const&>(),
                                                   std::declval<scalar const&>())),
                   boost::system::result<secp::public_key>>);
static_assert(
    std::is_same_v<decltype(secp::pubkey_tweak_mul(std::declval<secp::public_key const&>(),
                                                   std::declval<scalar const&>())),
                   boost::system::result<secp::public_key>>);
static_assert(std::is_same_v<decltype(secp::pubkey_negate(std::declval<secp::public_key const&>())),
                             boost::system::result<secp::public_key>>);
static_assert(std::is_same_v<secp::workspace, std::span<std::byte>>);
static_assert(secp::combine_workspace_size(2) ==
              (2 * sizeof(secp256k1_pubkey const*)) + alignof(std::max_align_t));
static_assert(noexcept(secp::pubkey_negate(std::declval<secp::public_key const&>())));

scalar to_scalar(std::span<std::uint8_t const> bytes) {
    scalar out{};
    std::ranges::copy(bytes.first(32), out.begin());
    return out;
}

scalar order() {
    return to_scalar(test::from_hex(order_hex));
}

scalar small(std::uint8_t k) {
    scalar out{};
    out.back() = k;
    return out;
}

// n - x in unsigned arithmetic, for x below the group order n.
scalar order_minus(std::span<std::uint8_t const, 32> x) {
    auto const n = order();
    scalar out{};
    unsigned borrow = 0;
    for (std::size_t i = 32; i-- > 0;) {
        unsigned const d = unsigned{n[i]} - unsigned{x[i]} - borrow;
        out[i] = static_cast<std::uint8_t>(d & 0xffU);
        borrow = (d >> 8U) & 1U;
    }
    return out;
}

// A scalar from the generator that libsecp256k1 takes as a secret key: not zero, below n.
scalar draw(std::mt19937_64& generator) {
    for (;;) {
        scalar out{};
        for (auto& octet : out) {
            octet = static_cast<std::uint8_t>(generator());
        }
        if (secp256k1_ec_seckey_verify(secp256k1_context_static, out.data()) == 1) {
            return out;
        }
    }
}

// P(x): the public key of the secret x, through a key pair.
secp::public_key public_of(std::span<std::uint8_t const, 32> secret_bytes) {
    auto const key = secp::keypair::make(secret_bytes);
    if (!BOOST_TEST(key.has_value())) {
        std::exit(boost::report_errors());
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        std::exit(boost::report_errors());
    }
    return *public_key;
}

// The compressed bytes of a key libsecp256k1's C API computed.
std::array<std::uint8_t, 33> c_bytes(secp256k1_pubkey const& point) {
    std::array<std::uint8_t, 33> out{};
    std::size_t size = out.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_COMPRESSED;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, out.data(), &size, &point, flags);
    return out;
}

secp256k1_pubkey c_point(secp::public_key const& key) {
    auto const encoded = key.compressed();
    secp256k1_pubkey out{};
    BOOST_TEST(secp256k1_ec_pubkey_parse(secp256k1_context_static, &out, encoded.data(),
                                         encoded.size()) == 1);
    return out;
}

bool all_zero(std::span<std::byte const> bytes) {
    return std::ranges::all_of(bytes, [](std::byte b) { return b == std::byte{0}; });
}

// The secret results of one round against libsecp256k1's C API, called directly on copies of d.
void secrets_against_c_api(scalar const& d, scalar const& t, crypto::secret<32> const& sum,
                           crypto::secret<32> const& product, crypto::secret<32> const& negated) {
    scalar c_sum = d;
    scalar c_product = d;
    scalar c_negated = d;
    BOOST_TEST(secp256k1_ec_seckey_tweak_add(secp256k1_context_static, c_sum.data(), t.data()) ==
               1);
    BOOST_TEST(
        secp256k1_ec_seckey_tweak_mul(secp256k1_context_static, c_product.data(), t.data()) == 1);
    BOOST_TEST(secp256k1_ec_seckey_negate(secp256k1_context_static, c_negated.data()) == 1);
    BOOST_TEST(std::ranges::equal(sum.bytes(), c_sum));
    BOOST_TEST(std::ranges::equal(product.bytes(), c_product));
    BOOST_TEST(std::ranges::equal(negated.bytes(), c_negated));
}

// The public results of one round against the C API: P + tG, tP, -P and P + T.
void keys_against_c_api(secp::public_key const& p_d, secp::public_key const& p_t, scalar const& t,
                        std::array<secp::public_key, 4> const& results) {
    auto c_added = c_point(p_d);
    auto c_multiplied = c_point(p_d);
    auto c_minus = c_point(p_d);
    BOOST_TEST(secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &c_added, t.data()) == 1);
    BOOST_TEST(secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &c_multiplied, t.data()) ==
               1);
    BOOST_TEST(secp256k1_ec_pubkey_negate(secp256k1_context_static, &c_minus) == 1);
    std::array<secp256k1_pubkey, 2> const c_pair{c_point(p_d), c_point(p_t)};
    std::array<secp256k1_pubkey const*, 2> const c_pointers{c_pair.data(), c_pair.data() + 1};
    secp256k1_pubkey c_combined{};
    BOOST_TEST(secp256k1_ec_pubkey_combine(secp256k1_context_static, &c_combined, c_pointers.data(),
                                           c_pointers.size()) == 1);
    std::array<secp256k1_pubkey const*, 4> const expected{
        &c_added,
        &c_multiplied,
        &c_minus,
        &c_combined,
    };
    for (std::size_t i = 0; i < results.size(); ++i) {
        BOOST_TEST(std::ranges::equal(results.at(i).compressed(), c_bytes(*expected.at(i))));
    }
}

// One round: the identities, then each result against the C API.
void identity_round(scalar const& d, scalar const& t, secp::workspace space) {
    auto const p_d = public_of(d);
    auto const p_t = public_of(t);
    auto const sum = secp::seckey_tweak_add(d, t);
    auto const product = secp::seckey_tweak_mul(d, t);
    auto const negated = secp::seckey_negate(d);
    auto const p_sum = secp::pubkey_tweak_add(p_d, t);
    auto const p_product = secp::pubkey_tweak_mul(p_d, t);
    auto const p_negated = secp::pubkey_negate(p_d);
    std::array<secp::public_key, 2> const pair{p_d, p_t};
    auto const combined = secp::pubkey_combine(pair, space);
    BOOST_TEST(all_zero(space));
    if (!BOOST_TEST(sum && product && negated && p_sum && p_product && p_negated && combined)) {
        return;
    }
    BOOST_TEST(*p_sum == public_of(sum->bytes()));
    BOOST_TEST(*p_product == public_of(product->bytes()));
    BOOST_TEST(*p_negated == public_of(negated->bytes()));
    BOOST_TEST(*p_negated != p_d);
    auto const p_twice = secp::pubkey_negate(*p_negated);
    BOOST_TEST(p_twice.has_value() && *p_twice == p_d);
    BOOST_TEST(*combined == *p_sum);
    // -(-d) holds d's bytes; each step bound to a name (secret's views are lvalue-only).
    auto const twice = secp::seckey_negate(negated->bytes());
    BOOST_TEST(twice && std::ranges::equal(twice->bytes(), d));

    secrets_against_c_api(d, t, *sum, *product, *negated);
    keys_against_c_api(p_d, p_t, t, {*p_sum, *p_product, *p_negated, *combined});
}

void identities() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x7e3a6b1c0ffeeULL);
    alignas(std::max_align_t) std::array<std::byte, secp::combine_workspace_size(2)> space{};
    for (int round = 0; round < 64; ++round) {
        auto const d = draw(generator);
        auto const t = draw(generator);
        identity_round(d, t, space);
    }
}

// More keys than two, and one key alone, against the sum of their secrets.
void combinations() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xc0b1e5ULL);
    std::vector<scalar> secrets;
    std::vector<secp::public_key> keys;
    for (int i = 0; i < 5; ++i) {
        secrets.push_back(draw(generator));
        keys.push_back(public_of(secrets.back()));
    }
    scalar total = secrets[0];
    for (std::size_t i = 1; i < secrets.size(); ++i) {
        BOOST_TEST(secp256k1_ec_seckey_tweak_add(secp256k1_context_static, total.data(),
                                                 secrets[i].data()) == 1);
    }
    std::vector<std::byte> space(secp::combine_workspace_size(keys.size()));
    auto const combined = secp::pubkey_combine(keys, space);
    BOOST_TEST(combined && *combined == public_of(total));
    BOOST_TEST(all_zero(space));

    alignas(std::max_align_t) std::array<std::byte, secp::combine_workspace_size(1)> one{};
    auto const alone = secp::pubkey_combine(std::span(keys).first(1), one);
    BOOST_TEST(alone && *alone == keys[0]);
    BOOST_TEST(all_zero(one));
}

// A workspace that starts off the alignment, at every offset below alignof(std::max_align_t):
// the keys' pointers start at the next aligned byte, which combine_workspace_size's padding
// pays for. The workspace is filled with a guard byte before each call and is zero after it,
// the padding before the pointers and the bytes after them included; the bytes around it are
// not touched.
void off_alignment() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xa1196eULL);
    std::array<scalar, 3> secrets{};
    for (auto& secret_bytes : secrets) {
        secret_bytes = draw(generator);
    }
    std::array<secp::public_key, 3> const keys{
        public_of(secrets[0]),
        public_of(secrets[1]),
        public_of(secrets[2]),
    };
    scalar total = secrets[0];
    for (std::size_t i = 1; i < secrets.size(); ++i) {
        BOOST_TEST(secp256k1_ec_seckey_tweak_add(secp256k1_context_static, total.data(),
                                                 secrets.at(i).data()) == 1);
    }
    auto const expected = public_of(total);
    constexpr std::size_t space_size = secp::combine_workspace_size(3);
    constexpr std::byte guard{0x5a};
    for (std::size_t offset = 1; offset < alignof(std::max_align_t); ++offset) {
        alignas(std::max_align_t) std::array<std::byte, space_size + alignof(std::max_align_t)>
            buffer{};
        buffer.fill(guard);
        auto const space = std::span(buffer).subspan(offset, space_size);
        auto const combined = secp::pubkey_combine(keys, space);
        BOOST_TEST(combined && *combined == expected);
        BOOST_TEST(all_zero(space));
        auto const is_guard = [](std::byte b) { return b == guard; };
        BOOST_TEST(std::ranges::all_of(std::span(buffer).first(offset), is_guard));
        BOOST_TEST(std::ranges::all_of(std::span(buffer).subspan(offset + space_size), is_guard));
    }
}

// 1 + 1 is 2, whose public key is 2G.
void known_answer() {
    auto const two = secp::seckey_tweak_add(small(1), small(1));
    if (!BOOST_TEST(two.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(two->bytes(), small(2)));
    auto const key = public_of(two->bytes());
    BOOST_TEST_EQ(test::to_hex(key.compressed()),
                  "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
    auto const added = secp::pubkey_tweak_add(public_of(small(1)), small(1));
    BOOST_TEST(added && *added == key);
}

template <class Result>
void refused(char const* name, Result const& result, crypto::error expected) {
    if (!BOOST_TEST(result.has_error()) || !BOOST_TEST(result.error() == expected)) {
        BOOST_ERROR(name);
    }
}

void refusals() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x5eedULL);
    auto const d = draw(generator);
    auto const p_d = public_of(d);
    auto const n = order();
    scalar const zero{};
    auto const n_minus_d = order_minus(d);

    // A tweak equal to the group order.
    refused("seckey_tweak_add(d, n)", secp::seckey_tweak_add(d, n),
            crypto::error::invalid_secret_key);
    refused("seckey_tweak_mul(d, n)", secp::seckey_tweak_mul(d, n),
            crypto::error::invalid_secret_key);
    refused("pubkey_tweak_add(P, n)", secp::pubkey_tweak_add(p_d, n),
            crypto::error::invalid_secret_key);
    refused("pubkey_tweak_mul(P, n)", secp::pubkey_tweak_mul(p_d, n),
            crypto::error::invalid_secret_key);
    // A sum that is zero, and a product by zero.
    refused("seckey_tweak_add(d, n - d)", secp::seckey_tweak_add(d, n_minus_d),
            crypto::error::invalid_secret_key);
    refused("pubkey_tweak_add(P(d), n - d)", secp::pubkey_tweak_add(p_d, n_minus_d),
            crypto::error::invalid_secret_key);
    refused("seckey_tweak_mul(d, 0)", secp::seckey_tweak_mul(d, zero),
            crypto::error::invalid_secret_key);
    refused("pubkey_tweak_mul(P, 0)", secp::pubkey_tweak_mul(p_d, zero),
            crypto::error::invalid_secret_key);
    // A zero and an order-sized secret.
    for (auto const& bad : {zero, n}) {
        refused("seckey_tweak_add(bad, t)", secp::seckey_tweak_add(bad, small(1)),
                crypto::error::invalid_secret_key);
        refused("seckey_tweak_mul(bad, t)", secp::seckey_tweak_mul(bad, small(1)),
                crypto::error::invalid_secret_key);
        refused("seckey_negate(bad)", secp::seckey_negate(bad), crypto::error::invalid_secret_key);
    }
    // A zero tweak adds nothing: d + 0 is d.
    auto const same = secp::seckey_tweak_add(d, zero);
    BOOST_TEST(same && std::ranges::equal(same->bytes(), d));

    // P + (-P) is the point at infinity.
    alignas(std::max_align_t) std::array<std::byte, secp::combine_workspace_size(2)> space{};
    auto const p_opposite = secp::pubkey_negate(p_d);
    if (!BOOST_TEST(p_opposite.has_value())) {
        return;
    }
    std::array<secp::public_key, 2> const opposite{p_d, *p_opposite};
    refused("pubkey_combine(P, -P)", secp::pubkey_combine(opposite, space),
            crypto::error::invalid_public_key);
    BOOST_TEST(all_zero(space));
    // No keys, and a workspace one byte short: refused, and the workspace, lent full of
    // non-zero bytes, is zero afterwards all the same.
    std::ranges::fill(space, std::byte{0xa5});
    refused("pubkey_combine({})", secp::pubkey_combine({}, space),
            crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(space));
    std::ranges::fill(space, std::byte{0xa5});
    std::array<secp::public_key, 2> const pair{p_d, public_of(small(7))};
    refused("pubkey_combine(short)",
            secp::pubkey_combine(pair, std::span(space).first(space.size() - 1)),
            crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(std::span(space).first(space.size() - 1)));
    refused("pubkey_combine(no workspace)", secp::pubkey_combine(pair, {}),
            crypto::error::invalid_input_size);
}

}  // namespace

int main() {
    identities();
    combinations();
    off_alignment();
    known_answer();
    refusals();
    return webcpp::test::exit_status(boost::report_errors());
}
