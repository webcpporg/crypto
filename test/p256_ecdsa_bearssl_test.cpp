// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 ECDSA on BearSSL, sign(ecdsa_sha256, input) and crypto::verify: RFC 6979's two SHA-256
// signatures byte for byte, low S (the "sample" one normalized), the same on every signing, from
// the message and from its digest; verification of both forms of a signature and every refusal
// (a bit of the digest, of r or of s, another key, r or s 0 or n), and the digests 0 modulo n
// that BearSSL refuses; a 32-byte message hashed, never read as a digest; the empty message;
// is_low_s and normalize_low_s at their boundary; low S over 1,000 signatures of random digests
// under a key and 256 of random messages under keys of their own, all drawn from a printed seed
// that a define replays; DER both ways against encodings written by hand, the short buffer, the
// strict decoder's refusals and integers shorter than 32 bytes.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
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
using webcpp::test::hex;
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

// The bytes of a text, as a message.
std::span<std::uint8_t const> text_bytes(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// n - s, the other s of a signature, for 0 < s < n: big-endian subtraction with a borrow.
std::array<std::uint8_t, 32> negated(std::span<std::uint8_t const, 32> s) {
    std::array<std::uint8_t, 32> out{};
    unsigned borrow = 0;
    for (std::size_t i = out.size(); i-- > 0;) {
        unsigned const difference = static_cast<unsigned>(data::order[i]) - s[i] - borrow;
        out[i] = static_cast<std::uint8_t>(difference);
        borrow = (difference >> 8U) & 1U;
    }
    return out;
}

// RFC 6979's two digests, signed through the marker: the "test" signature, whose S is low, byte
// for byte, and the "sample" one in its low-S form, the RFC's S being high; the same on every
// signing.
void rfc6979_signatures() {
    auto const key = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const sample = key->sign(crypto::ecdsa_sha256, crypto::prehashed{sha256("sample")});
    auto const test = key->sign(crypto::ecdsa_sha256, crypto::prehashed{sha256("test")});
    if (BOOST_TEST(sample.has_value()) && BOOST_TEST(test.has_value())) {
        BOOST_TEST(*sample == data::rfc6979_sample_low_s);
        BOOST_TEST(*test == data::rfc6979_test);
    }
    auto const again = key->sign(crypto::ecdsa_sha256, crypto::prehashed{sha256("sample")});
    if (BOOST_TEST(again.has_value()) && sample.has_value()) {
        BOOST_TEST(*again == *sample);
    }
}

// sign's normalization after BearSSL signs: RFC 6979's "sample", whose raw S is high, comes out
// with the same r and n - s; its "test", whose raw S is low, comes out byte for byte as the RFC
// gives it. And the constant-time mask sign selects with, at its boundary: 0xff exactly above
// (n - 1) / 2.
void sign_normalizes_raw_s() {
    auto const key = keypair::make(data::rfc6979_scalar);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const sample = key->sign(crypto::ecdsa_sha256, text_bytes("sample"));
    auto const test = key->sign(crypto::ecdsa_sha256, text_bytes("test"));
    if (BOOST_TEST(sample.has_value()) && BOOST_TEST(test.has_value())) {
        BOOST_TEST(std::ranges::equal(r_of(*sample), r_of(data::rfc6979_sample)));
        BOOST_TEST(std::ranges::equal(s_of(*sample), negated(s_of(data::rfc6979_sample))));
        BOOST_TEST(*test == data::rfc6979_test);
    }

    using p256_family = crypto::families::p256;
    auto above_half = data::half_order;
    ++above_half.back();  // ends with a8: no carry
    std::array<std::uint8_t, 32> one{};
    one.back() = 1;
    auto order_minus_one = data::order;
    --order_minus_one.back();  // ends with 51: no borrow
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(data::half_order),
                  std::uint8_t{0x00});
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(above_half), std::uint8_t{0xff});
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(one), std::uint8_t{0x00});
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(order_minus_one),
                  std::uint8_t{0xff});
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(s_of(data::rfc6979_sample)),
                  std::uint8_t{0xff});
    BOOST_TEST_EQ(crypto::detail::p_curve_high_s_mask<p256_family>(s_of(data::rfc6979_test)),
                  std::uint8_t{0x00});
}

// RFC 6979, section A.2.5, the message "sample" itself, hashed inside sign: the section's r, and
// n - s for the section's s, which is high; crypto::verify accepts the section's own high-S
// signature as well as sign's; is_low_s tells the two apart, and normalize_low_s of the
// section's signature is sign's.
void rfc6979_sample_message() {
    auto const key = keypair::make(data::rfc6979_scalar);
    auto const verifier = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(verifier.has_value())) {
        return;
    }
    auto const section_r =
        hex<32>("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    auto const section_s =
        hex<32>("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");
    auto const section = joined(section_r, section_s);
    auto const signed_message = key->sign(crypto::ecdsa_sha256, text_bytes("sample"));
    if (!BOOST_TEST(signed_message.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(r_of(*signed_message), section_r));
    BOOST_TEST(std::ranges::equal(s_of(*signed_message), negated(section_s)));
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, section, text_bytes("sample"), *verifier).has_value());
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signed_message, text_bytes("sample"), *verifier)
            .has_value());
    BOOST_TEST(!p256::is_low_s(section));
    BOOST_TEST(p256::is_low_s(*signed_message));
    auto const normalized = p256::normalize_low_s(section);
    if (BOOST_TEST(normalized.has_value())) {
        BOOST_TEST(*normalized == *signed_message);
    }
}

void verify_both_forms() {
    auto const key = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const sample = sha256("sample");
    auto const test = sha256("test");
    auto const verified = [](signature const& value, digest const& hash,
                             public_key const& verifier) {
        return crypto::verify(crypto::ecdsa_sha256, value, crypto::prehashed{hash}, verifier);
    };
    BOOST_TEST(verified(data::rfc6979_sample, sample, *key).has_value());
    BOOST_TEST(verified(data::rfc6979_sample_low_s, sample, *key).has_value());
    BOOST_TEST(verified(data::rfc6979_test, test, *key).has_value());

    auto const refused = [&key, &verified](signature const& value, digest const& hash) {
        return verified(value, hash, *key).error() == error::invalid_signature;
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
        BOOST_TEST(verified(value, hash, *other_key).error() == error::invalid_signature);
    }

    std::array<std::uint8_t, 32> const zero{};
    BOOST_TEST(refused(joined(zero, s_of(data::rfc6979_test)), test));
    BOOST_TEST(refused(joined(r_of(data::rfc6979_test), zero), test));
    BOOST_TEST(refused(joined(data::order, s_of(data::rfc6979_test)), test));
    BOOST_TEST(refused(joined(r_of(data::rfc6979_test), data::order), test));
}

// A 32-byte message is a message: sign hashes it, as any other, and never reads it as a digest;
// verify likewise, so the marker of the same bytes is another input, refused.
void message_is_hashed() {
    auto const key = keypair::make(data::rfc6979_scalar);
    auto const verifier = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(verifier.has_value())) {
        return;
    }
    std::array<std::uint8_t, 32> message{};
    for (std::size_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<std::uint8_t>((i * 7) + 1);
    }
    auto const of_message = key->sign(crypto::ecdsa_sha256, message);
    auto const of_digest =
        key->sign(crypto::ecdsa_sha256, crypto::prehashed{crypto::detail::sha256_of(message)});
    auto const of_marker = key->sign(crypto::ecdsa_sha256, crypto::prehashed{message});
    if (!BOOST_TEST(of_message.has_value()) || !BOOST_TEST(of_digest.has_value()) ||
        !BOOST_TEST(of_marker.has_value())) {
        return;
    }
    BOOST_TEST(*of_message == *of_digest);
    BOOST_TEST(*of_message != *of_marker);
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *of_message, message, *verifier).has_value());
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *of_message, crypto::prehashed{message}, *verifier)
            .error() == error::invalid_signature);
}

// The empty message is a message: signed, its SHA-256 signed, and verified.
void empty_message() {
    auto const key = keypair::make(data::rfc6979_scalar);
    auto const verifier = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(verifier.has_value())) {
        return;
    }
    std::span<std::uint8_t const> const empty{};
    auto const signed_empty = key->sign(crypto::ecdsa_sha256, empty);
    if (!BOOST_TEST(signed_empty.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *signed_empty, empty, *verifier).has_value());
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *signed_empty,
                              crypto::prehashed{crypto::detail::sha256_of(empty)}, *verifier)
                   .has_value());
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, *signed_empty, text_bytes("x"), *verifier).error() ==
        error::invalid_signature);
}

// A digest that is 0 modulo n (32 zero bytes, or n) signs, and BearSSL's verification refuses
// it, since it refuses a zero multiplier (bearssl_ec.h, muladd): crypto::verify's documented
// limit, pinned here so that a BearSSL that changes it is noticed. No SHA-256 of a message gives
// either.
void zero_digest() {
    auto const key = keypair::make(data::rfc6979_scalar);
    auto const verifier = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(verifier.has_value())) {
        return;
    }
    for (digest const& hash : {digest{}, data::order}) {
        auto const signed_hash = key->sign(crypto::ecdsa_sha256, crypto::prehashed{hash});
        if (BOOST_TEST(signed_hash.has_value())) {
            BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *signed_hash, crypto::prehashed{hash},
                                      *verifier)
                           .error() == error::invalid_signature);
        }
    }
}

void low_s() {
    BOOST_TEST(!p256::is_low_s(data::rfc6979_sample));
    BOOST_TEST(p256::is_low_s(data::rfc6979_sample_low_s));
    BOOST_TEST(p256::is_low_s(data::rfc6979_test));
    auto const normalized = p256::normalize_low_s(data::rfc6979_sample);
    if (BOOST_TEST(normalized.has_value())) {
        BOOST_TEST(*normalized == data::rfc6979_sample_low_s);
    }
    auto const unchanged = p256::normalize_low_s(data::rfc6979_test);
    if (BOOST_TEST(unchanged.has_value())) {
        BOOST_TEST(*unchanged == data::rfc6979_test);
    }

    // The boundary: (n - 1) / 2 is low, one more is high and normalizes to (n - 1) / 2.
    auto const r = r_of(data::rfc6979_sample);
    auto const half = joined(r, data::half_order);
    auto above_half = data::half_order;
    ++above_half.back();  // ends with a8: no carry
    BOOST_TEST(p256::is_low_s(half));
    BOOST_TEST(!p256::is_low_s(joined(r, above_half)));
    auto const lowered = p256::normalize_low_s(joined(r, above_half));
    if (BOOST_TEST(lowered.has_value())) {
        BOOST_TEST(*lowered == half);
    }

    std::array<std::uint8_t, 32> const zero{};
    auto const s = s_of(data::rfc6979_test);
    for (auto const& out_of_range :
         {joined(zero, s), joined(r, zero), joined(data::order, s), joined(r, data::order)}) {
        BOOST_TEST(p256::normalize_low_s(out_of_range).error() == error::invalid_signature);
        BOOST_TEST(!p256::is_low_s(out_of_range));
    }
}

// The seed of the random cases: drawn on each run and printed; a run is replayed by building
// with the printed value, define=WEBCPP_TEST_P256_SEED=<seed> on b2's command line, with -a or a
// build directory of its own, since a define alone does not make b2 build the test again.
std::uint64_t random_seed() {
#ifdef WEBCPP_TEST_P256_SEED
    return WEBCPP_TEST_P256_SEED;
#else
    return std::random_device{}();
#endif
}

// Bytes drawn from a seeded generator.
void draw(std::mt19937_64& generator, std::span<std::uint8_t> bytes) {
    std::ranges::generate(bytes, [&generator] { return static_cast<std::uint8_t>(generator()); });
}

// A key pair whose scalar is drawn from the generator, so that a seed replays the whole run.
keypair drawn_keypair(std::mt19937_64& generator) {
    std::array<std::uint8_t, 32> scalar{};
    draw(generator, scalar);
    auto key = keypair::make(scalar);
    while (!key) {
        draw(generator, scalar);
        key = keypair::make(scalar);
    }
    return std::move(*key);
}

// 1,000 signatures of random digests under a key: each low S, verified, and its high-S form,
// n - s, verified too, is_low_s false on it, and normalize_low_s of it gives the signature back.
void low_s_random(std::uint64_t seed) {
    std::mt19937_64 generator(seed);
    auto const key = drawn_keypair(generator);
    auto const verifier = key.public_key();
    if (!BOOST_TEST(verifier.has_value())) {
        return;
    }
    for (int i = 0; i < 1000; ++i) {
        digest hash{};
        draw(generator, hash);
        auto const signed_hash = key.sign(crypto::ecdsa_sha256, crypto::prehashed{hash});
        if (!BOOST_TEST(signed_hash.has_value())) {
            return;
        }
        BOOST_TEST(p256::is_low_s(*signed_hash));
        BOOST_TEST(
            crypto::verify(crypto::ecdsa_sha256, *signed_hash, crypto::prehashed{hash}, *verifier)
                .has_value());
        auto const high = joined(r_of(*signed_hash), negated(s_of(*signed_hash)));
        BOOST_TEST(!p256::is_low_s(high));
        BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, high, crypto::prehashed{hash}, *verifier)
                       .has_value());
        auto const normalized = p256::normalize_low_s(high);
        if (!BOOST_TEST(normalized.has_value())) {
            return;
        }
        BOOST_TEST(*normalized == *signed_hash);
    }
}

// 256 signatures of random messages, of random lengths, each under a key of its own: every one
// low S, and verified.
void always_low_s(std::uint64_t seed) {
    std::mt19937_64 generator(seed ^ 0x9e3779b97f4a7c15ULL);
    for (int i = 0; i < 256; ++i) {
        auto const key = drawn_keypair(generator);
        auto const verifier = key.public_key();
        bytes message(static_cast<std::size_t>(generator() % 200));
        draw(generator, message);
        auto const signed_message = key.sign(crypto::ecdsa_sha256, message);
        if (!BOOST_TEST(signed_message.has_value()) || !BOOST_TEST(verifier.has_value())) {
            return;
        }
        BOOST_TEST(p256::is_low_s(*signed_message));
        BOOST_TEST(
            crypto::verify(crypto::ecdsa_sha256, *signed_message, message, *verifier).has_value());
    }
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
    rfc6979_sample_message();
    sign_normalizes_raw_s();
    verify_both_forms();
    message_is_hashed();
    empty_message();
    zero_digest();
    low_s();
    std::uint64_t const seed = random_seed();
    std::cout << "p256_ecdsa_bearssl: seed " << seed
              << " (replay: define=WEBCPP_TEST_P256_SEED=" << seed << ")\n";
    low_s_random(seed);
    always_low_s(seed);
    der_round_trip();
    der_strict();
    der_short_integers();
    return webcpp::test::exit_status(boost::report_errors());
}
