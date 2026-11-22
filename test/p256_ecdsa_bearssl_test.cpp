// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 ECDSA on BearSSL: RFC 6979's two SHA-256 signatures byte for byte, the same on every
// signing; verification of both forms of a signature and every refusal (a bit of the digest, of
// r or of s, another key, r or s 0 or n), and the digests 0 modulo n that BearSSL refuses; low S,
// checked and normalized, at its boundary and over 1,000 signatures of random digests under a
// key, both drawn from a printed seed that a define replays; DER both
// ways against encodings written by hand, the short buffer, the strict decoder's refusals and
// integers shorter than 32 bytes.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/p256_data.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iostream>
#include <random>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;
namespace data = webcpp::test::p256;

using crypto::error;
using p256::keypair;
using p256::public_key;
using bytes = std::vector<std::uint8_t>;
using signature = std::array<std::uint8_t, p256::signature_size>;
using digest = std::array<std::uint8_t, p256::digest_size>;

// The SHA-256 of a text, with webcpp::hash.
digest sha256(std::string_view text) {
    digest out{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    auto const* const bytes = reinterpret_cast<std::uint8_t const*>(text.data());
    std::span<std::uint8_t const> const input(bytes, text.size());
    BOOST_TEST(webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(out, input).has_value());
    return out;
}

// r and s of a signature, put together.
signature joined(std::span<std::uint8_t const, 32> r, std::span<std::uint8_t const, 32> s) {
    signature out{};
    std::ranges::copy(r, out.begin());
    std::ranges::copy(s, out.begin() + 32);
    return out;
}

std::span<std::uint8_t const, 32> r_of(signature const& value) {
    return std::span<std::uint8_t const, 64>(value).first<32>();
}

std::span<std::uint8_t const, 32> s_of(signature const& value) {
    return std::span<std::uint8_t const, 64>(value).last<32>();
}

// Bytes put together, as a DER is written by hand: its headers and its integers.
bytes concat(std::initializer_list<std::span<std::uint8_t const>> parts) {
    bytes out;
    for (auto const part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

bytes header(std::initializer_list<std::uint8_t> values) {
    return values;
}

void rfc6979_signatures() {
    auto const key = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const sample = key->sign_ecdsa(sha256("sample"));
    auto const test = key->sign_ecdsa(sha256("test"));
    if (BOOST_TEST(sample.has_value()) && BOOST_TEST(test.has_value())) {
        BOOST_TEST(*sample == data::rfc6979_sample);
        BOOST_TEST(*test == data::rfc6979_test);
    }
    auto const again = key->sign_ecdsa(sha256("sample"));
    if (BOOST_TEST(again.has_value()) && sample.has_value()) {
        BOOST_TEST(*again == *sample);
    }
}

void verify_both_forms() {
    auto const key = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const sample = sha256("sample");
    auto const test = sha256("test");
    BOOST_TEST(p256::verify_ecdsa(data::rfc6979_sample, sample, *key).has_value());
    BOOST_TEST(p256::verify_ecdsa(data::rfc6979_sample_low_s, sample, *key).has_value());
    BOOST_TEST(p256::verify_ecdsa(data::rfc6979_test, test, *key).has_value());

    auto const refused = [&key](signature const& value, digest const& hash) {
        return p256::verify_ecdsa(value, hash, *key).error() == error::invalid_signature;
    };
    BOOST_TEST(refused(data::rfc6979_test, sample));
    BOOST_TEST(refused(data::rfc6979_sample, test));

    auto const other = keypair::generate();
    auto const other_key = other ? other->public_key() : other.error();
    if (!BOOST_TEST(other_key.has_value())) {
        return;
    }
    // Each signature, the RFC's high S, its low-S form and the low "test" one: one bit of the
    // digest, of r or of s flipped, and another key, each refused.
    for (auto const& [value, hash] : {
             std::pair{data::rfc6979_sample, sample},
             std::pair{data::rfc6979_sample_low_s, sample},
             std::pair{data::rfc6979_test, test},
         }) {
        auto flipped_digest = hash;
        flipped_digest[7] ^= 0x10U;
        BOOST_TEST(refused(value, flipped_digest));
        auto flipped_r = value;
        flipped_r[3] ^= 0x01U;
        BOOST_TEST(refused(flipped_r, hash));
        auto flipped_s = value;
        flipped_s[60] ^= 0x80U;
        BOOST_TEST(refused(flipped_s, hash));
        BOOST_TEST(p256::verify_ecdsa(value, hash, *other_key).error() == error::invalid_signature);
    }

    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(refused(joined(zero, s_of(data::rfc6979_test)), test));
    BOOST_TEST(refused(joined(r_of(data::rfc6979_test), zero), test));
    BOOST_TEST(refused(joined(data::order, s_of(data::rfc6979_test)), test));
    BOOST_TEST(refused(joined(r_of(data::rfc6979_test), data::order), test));
}

// A digest that is 0 modulo n (32 zero bytes, or n) signs, and BearSSL's verification refuses
// it, since it refuses a zero multiplier (bearssl_ec.h, muladd): verify_ecdsa's documented limit,
// pinned here so that a BearSSL that changes it is noticed. No SHA-256 of a message gives either.
void zero_digest() {
    auto const key = keypair::make(data::rfc6979_scalar);
    auto const verifier = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(verifier.has_value())) {
        return;
    }
    for (digest const& hash : {digest{}, data::order}) {
        auto const signed_hash = key->sign_ecdsa(hash);
        if (BOOST_TEST(signed_hash.has_value())) {
            BOOST_TEST(p256::verify_ecdsa(*signed_hash, hash, *verifier).error() ==
                       error::invalid_signature);
        }
    }
}

void low_s() {
    BOOST_TEST(p256::check_low_s(data::rfc6979_sample).error() == error::invalid_signature);
    BOOST_TEST(p256::check_low_s(data::rfc6979_sample_low_s).has_value());
    BOOST_TEST(p256::check_low_s(data::rfc6979_test).has_value());
    auto const normalized = p256::normalize_ecdsa(data::rfc6979_sample);
    if (BOOST_TEST(normalized.has_value())) {
        BOOST_TEST(*normalized == data::rfc6979_sample_low_s);
    }
    auto const unchanged = p256::normalize_ecdsa(data::rfc6979_test);
    if (BOOST_TEST(unchanged.has_value())) {
        BOOST_TEST(*unchanged == data::rfc6979_test);
    }

    // The boundary: (n - 1) / 2 is low, one more is high and normalizes to (n - 1) / 2.
    auto const r = r_of(data::rfc6979_sample);
    auto const half = joined(r, data::half_order);
    auto above_half = data::half_order;
    ++above_half.back();  // ends with a8: no carry
    BOOST_TEST(p256::check_low_s(half).has_value());
    BOOST_TEST(p256::check_low_s(joined(r, above_half)).error() == error::invalid_signature);
    auto const lowered = p256::normalize_ecdsa(joined(r, above_half));
    if (BOOST_TEST(lowered.has_value())) {
        BOOST_TEST(*lowered == half);
    }

    std::array<std::uint8_t, 32> const zero{};
    auto const s = s_of(data::rfc6979_test);
    for (auto const& out_of_range :
         {joined(zero, s), joined(r, zero), joined(data::order, s), joined(r, data::order)}) {
        BOOST_TEST(p256::normalize_ecdsa(out_of_range).error() == error::invalid_signature);
        BOOST_TEST(p256::check_low_s(out_of_range).error() == error::invalid_signature);
    }
}

// The seed of low_s_random: drawn on each run and printed; a run is replayed by building with
// the printed value, define=WEBCPP_TEST_P256_SEED=<seed> on b2's command line, with -a or a
// build directory of its own, since a define alone does not make b2 build the test again.
std::uint64_t random_seed() {
#ifdef WEBCPP_TEST_P256_SEED
    return WEBCPP_TEST_P256_SEED;
#else
    return std::random_device{}();
#endif
}

void low_s_random() {
    std::uint64_t const seed = random_seed();
    std::cout << "low_s_random: seed " << seed << " (replay: define=WEBCPP_TEST_P256_SEED=" << seed
              << ")\n";
    std::mt19937_64 generator(seed);
    auto const draw = [&generator](std::span<std::uint8_t> bytes) {
        std::ranges::generate(bytes,
                              [&generator] { return static_cast<std::uint8_t>(generator()); });
    };
    // The key is drawn from the seed too, so that the seed replays the whole run.
    std::array<std::uint8_t, 32> scalar{};
    draw(scalar);
    auto key = keypair::make(scalar);
    while (!key) {
        draw(scalar);
        key = keypair::make(scalar);
    }
    auto const verifier = key->public_key();
    if (!BOOST_TEST(verifier.has_value())) {
        return;
    }
    int high = 0;
    for (int i = 0; i < 1000; ++i) {
        digest hash{};
        draw(hash);
        auto const signed_hash = key->sign_ecdsa(hash);
        if (!BOOST_TEST(signed_hash.has_value())) {
            return;
        }
        BOOST_TEST(p256::verify_ecdsa(*signed_hash, hash, *verifier).has_value());
        if (!p256::check_low_s(*signed_hash)) {
            ++high;
        }
        auto const normalized = p256::normalize_ecdsa(*signed_hash);
        if (!BOOST_TEST(normalized.has_value())) {
            return;
        }
        BOOST_TEST(p256::check_low_s(*normalized).has_value());
        BOOST_TEST(p256::verify_ecdsa(*normalized, hash, *verifier).has_value());
    }
    std::cout << "low_s_random: " << high << " of 1000 had a high S\n";
    BOOST_TEST_GE(high, 400);
    BOOST_TEST_LE(high, 600);
}

void der_round_trip() {
    auto const r = r_of(data::rfc6979_sample);
    // The RFC's form: r and s both have their high bit set, so each takes a zero byte.
    bytes const rfc_der = concat({
        header({0x30, 0x46, 0x02, 0x21, 0x00}),
        r,
        header({0x02, 0x21, 0x00}),
        s_of(data::rfc6979_sample),
    });
    // The low-S form: s starts with 08, its integer has no zero byte.
    bytes const low_der = concat({
        header({0x30, 0x45, 0x02, 0x21, 0x00}),
        r,
        header({0x02, 0x20}),
        s_of(data::rfc6979_sample_low_s),
    });
    for (auto const& [value, expected] : {
             std::pair{data::rfc6979_sample, rfc_der},
             std::pair{data::rfc6979_sample_low_s, low_der},
         }) {
        std::array<std::uint8_t, p256::max_der_size> output{};
        auto const written = p256::to_der(value, output);
        if (!BOOST_TEST(written.has_value())) {
            continue;
        }
        BOOST_TEST_EQ(*written, expected.size());
        BOOST_TEST(std::ranges::equal(std::span(output).first(*written), expected));
        auto const decoded = p256::from_der(expected);
        if (BOOST_TEST(decoded.has_value())) {
            BOOST_TEST(*decoded == value);
        }
    }
    BOOST_TEST_EQ(rfc_der.size(), 72U);
    BOOST_TEST_EQ(low_der.size(), 71U);

    // A buffer shorter than max_der_size is refused whatever the signature's length, untouched.
    for (std::size_t const size : {std::size_t{71}, std::size_t{70}}) {
        bytes buffer(size, 0xa5);
        BOOST_TEST(p256::to_der(data::rfc6979_sample_low_s, buffer).error() ==
                   error::invalid_input_size);
        BOOST_TEST(std::ranges::all_of(buffer, [](std::uint8_t byte) { return byte == 0xa5; }));
    }

    std::array<std::uint8_t, 32> const zero{};
    std::array<std::uint8_t, p256::max_der_size> output{};
    BOOST_TEST(p256::to_der(joined(zero, s_of(data::rfc6979_test)), output).error() ==
               error::invalid_signature);
    BOOST_TEST(p256::to_der(joined(r, data::order), output).error() == error::invalid_signature);
}

void der_strict() {
    // r and s both 08 34 ..., the low-S form's s: their high bit is clear, no zero byte needed.
    auto const low = s_of(data::rfc6979_sample_low_s);
    auto const high = r_of(data::rfc6979_sample);
    bytes const strict = concat({header({0x30, 0x44, 0x02, 0x20}), low, header({0x02, 0x20}), low});
    BOOST_TEST(p256::from_der(strict).has_value());

    auto const refused = [](bytes const& der) {
        auto const decoded = p256::from_der(der);
        return !decoded.has_value() && decoded.error() == error::invalid_signature;
    };
    // A needless leading zero in r.
    BOOST_TEST(
        refused(concat({header({0x30, 0x45, 0x02, 0x21, 0x00}), low, header({0x02, 0x20}), low})));
    // The SEQUENCE's length in the long form, where the short one holds it.
    BOOST_TEST(
        refused(concat({header({0x30, 0x81, 0x44, 0x02, 0x20}), low, header({0x02, 0x20}), low})));
    // Bytes after the SEQUENCE.
    BOOST_TEST(refused(concat({strict, header({0x00})})));
    // A negative r: its high bit set, without the zero byte.
    BOOST_TEST(
        refused(concat({header({0x30, 0x44, 0x02, 0x20}), high, header({0x02, 0x20}), low})));
    // r = 0, and s = n.
    BOOST_TEST(refused(concat({header({0x30, 0x25, 0x02, 0x01, 0x00, 0x02, 0x20}), low})));
    BOOST_TEST(refused(
        concat({header({0x30, 0x45, 0x02, 0x20}), low, header({0x02, 0x21, 0x00}), data::order})));
    BOOST_TEST(refused({}));
}

void der_short_integers() {
    std::array<std::uint8_t, 32> one{};
    one.back() = 0x01;
    std::array<std::uint8_t, 32> two{};
    two.back() = 0x02;
    auto const low = s_of(data::rfc6979_sample_low_s);
    bytes const both_short = header({0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
    bytes const r_short = concat({header({0x30, 0x25, 0x02, 0x01, 0x01, 0x02, 0x20}), low});
    for (auto const& [value, expected] :
         {std::pair{joined(one, two), both_short}, std::pair{joined(one, low), r_short}}) {
        std::array<std::uint8_t, p256::max_der_size> output{};
        auto const written = p256::to_der(value, output);
        if (BOOST_TEST(written.has_value())) {
            BOOST_TEST(std::ranges::equal(std::span(output).first(*written), expected));
        }
        auto const decoded = p256::from_der(expected);
        if (BOOST_TEST(decoded.has_value())) {
            BOOST_TEST(*decoded == value);
        }
    }
}

}  // namespace

int main() {
    rfc6979_signatures();
    verify_both_forms();
    zero_digest();
    low_s();
    low_s_random();
    der_round_trip();
    der_strict();
    der_short_integers();
    return webcpp::test::exit_status(boost::report_errors());
}
