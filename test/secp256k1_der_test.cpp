// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's ECDSA encodings: compact to strict DER and back for signatures of sign_ecdsa,
// the strict decoder against Wycheproof's Bitcoin ECDSA vectors (DER, counted per flag), every
// refusal of to_der, and low-S normalization of a high-S signature.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using bytes = std::vector<std::uint8_t>;

// The group order n, big-endian.
constexpr std::string_view order_hex =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

std::array<std::uint8_t, 32> sha256(std::span<std::uint8_t const> data) {
    boost::hash2::sha2_256 hasher;
    hasher.update(data.data(), data.size());
    auto const digest = hasher.result();
    std::array<std::uint8_t, 32> out{};
    std::ranges::copy(digest, out.begin());
    return out;
}

// A key pair and a hash, both derived from i, so that the signatures vary in length.
secp::keypair key_of(std::uint8_t i) {
    std::array<std::uint8_t, 2> const seed{0x6b, i};
    return *secp::keypair::make(sha256(seed));
}

// n - s of a compact signature, in unsigned arithmetic: its high-S twin.
std::array<std::uint8_t, 64> negate_s(std::span<std::uint8_t const, 64> compact) {
    auto const order = test::from_hex(order_hex);
    std::array<std::uint8_t, 64> out{};
    std::ranges::copy(compact, out.begin());
    unsigned borrow = 0;
    for (std::size_t i = 32; i-- > 0;) {
        unsigned const d = unsigned{order[i]} - unsigned{compact[32 + i]} - borrow;
        out[32 + i] = static_cast<std::uint8_t>(d & 0xffU);
        borrow = (d >> 8U) & 1U;
    }
    return out;
}

// Strict DER of a signature: SEQUENCE of two minimal, non-negative INTEGERs, nothing after.
bool strict(std::span<std::uint8_t const> der) {
    auto const integer = [&](std::size_t at) -> std::size_t {
        if (at + 2 > der.size() || der[at] != 0x02) {
            return 0;
        }
        std::size_t const length = der[at + 1];
        if (length == 0 || at + 2 + length > der.size() || (der[at + 2] & 0x80U) != 0 ||
            (length > 1 && der[at + 2] == 0 && (der[at + 3] & 0x80U) == 0)) {
            return 0;
        }
        return at + 2 + length;
    };
    if (der.size() < 8 || der[0] != 0x30 || der[1] != der.size() - 2) {
        return false;
    }
    auto const after_r = integer(2);
    return after_r != 0 && integer(after_r) == der.size();
}

void round_trips() {
    int signed_count = 0;
    std::size_t shortest = secp::max_der_size;
    std::size_t longest = 0;
    for (unsigned i = 0; i < 256; ++i) {
        auto const key = key_of(static_cast<std::uint8_t>(i));
        std::array<std::uint8_t, 2> const message{0x6d, static_cast<std::uint8_t>(i)};
        auto const signature = key.sign_ecdsa(sha256(message));
        BOOST_TEST(signature.has_value());
        std::array<std::uint8_t, secp::max_der_size> der{};
        auto const written = secp::to_der(*signature, der);
        BOOST_TEST(written.has_value());
        if (!written) {
            continue;
        }
        ++signed_count;
        shortest = std::min(shortest, *written);
        longest = std::max(longest, *written);
        auto const encoded = std::span<std::uint8_t const>(der).first(*written);
        BOOST_TEST(*written <= secp::max_der_size);
        BOOST_TEST(strict(encoded));
        auto const decoded = secp::from_der(encoded);
        BOOST_TEST(decoded.has_value() && *decoded == *signature);
    }
    std::cout << "round trips: " << signed_count << ", DER of " << shortest << " to " << longest
              << " bytes\n";
    BOOST_TEST_EQ(signed_count, 256);
    // Low-S signatures of 256 random hashes: some r has its top bit set (a 33-byte integer),
    // and some r or s is shorter than 32 bytes.
    BOOST_TEST_EQ(longest, 71U);
    BOOST_TEST_LT(shortest, 70U);
}

void to_der_refusals() {
    auto const key = key_of(1);
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x31);
    auto const signature = *key.sign_ecdsa(hash);

    // Too short for the longest encoding, even when this one would fit: nothing is written.
    std::array<std::uint8_t, secp::max_der_size - 1> short_out{};
    short_out.fill(0xa5);
    BOOST_TEST(secp::to_der(signature, short_out).error() == crypto::error::invalid_input_size);
    BOOST_TEST(std::ranges::all_of(short_out, [](std::uint8_t b) { return b == 0xa5; }));

    // r not below the group order, and a zero s, are not signatures.
    std::array<std::uint8_t, secp::max_der_size> out{};
    out.fill(0xa5);
    auto overflowing = signature;
    std::ranges::fill(std::span(overflowing).first(32), std::uint8_t{0xff});
    BOOST_TEST(secp::to_der(overflowing, out).error() == crypto::error::invalid_signature);
    auto zero_s = signature;
    std::ranges::fill(std::span(zero_s).last(32), std::uint8_t{0});
    BOOST_TEST(secp::to_der(zero_s, out).error() == crypto::error::invalid_signature);
    BOOST_TEST(std::ranges::all_of(out, [](std::uint8_t b) { return b == 0xa5; }));

    // The decoder refuses the empty input, which has no data to give libsecp256k1.
    BOOST_TEST(secp::from_der({}).error() == crypto::error::invalid_signature);
}

void normalization() {
    auto const key = key_of(2);
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x77);
    auto const signature = *key.sign_ecdsa(hash);
    auto const public_key = *key.public_key();
    auto const high = negate_s(signature);
    BOOST_TEST(high != signature);
    BOOST_TEST(secp::verify_ecdsa(high, hash, public_key).error() ==
               crypto::error::invalid_signature);
    auto const normalized = secp::normalize_ecdsa(high);
    BOOST_TEST(normalized.has_value() && *normalized == signature);
    BOOST_TEST(normalized.has_value() && secp::verify_ecdsa(*normalized, hash, public_key));
    // Already low-S: unchanged.
    auto const again = secp::normalize_ecdsa(signature);
    BOOST_TEST(again.has_value() && *again == signature);
    // Not a signature.
    std::array<std::uint8_t, 64> overflowing{};
    overflowing.fill(0xff);
    BOOST_TEST(secp::normalize_ecdsa(overflowing).error() == crypto::error::invalid_signature);
}

// How many of a flag's cases the strict decoder accepts.
struct tally {
    int cases = 0;
    int strict = 0;
};

using tallies = std::map<std::string, tally>;

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

// One case through the strict decoder, counted in all and under each of its flags.
void decode_case(json::value const& t, tallies& per_flag, tally& all) {
    auto const der = test::from_hex(str(t.at("sig")));
    auto const strict_result = secp::from_der(der);
    if (str(t.at("result")) == "valid") {
        BOOST_TEST(strict_result.has_value());
    }
    auto const count = [&](tally& c) {
        ++c.cases;
        c.strict += strict_result ? 1 : 0;
    };
    count(all);
    for (auto const& flag : t.at("flags").as_array()) {
        count(per_flag[str(flag)]);
    }
}

// Measured on libsecp256k1 v0.8.0 and Wycheproof at 12fd3aa. A number not below the group
// order is refused, which is why IntegerOverflow and RangeCheck accept nothing.
tallies const& expected_tallies() {
    static tallies const expected{
        {"ArithmeticError", {.cases = 91, .strict = 87}},
        {"BerEncodedSignature", {.cases = 7, .strict = 0}},
        {"EdgeCasePublicKey", {.cases = 18, .strict = 18}},
        {"EdgeCaseShamirMultiplication", {.cases = 1, .strict = 1}},
        {"IntegerOverflow", {.cases = 5, .strict = 0}},
        {"InvalidEncoding", {.cases = 89, .strict = 0}},
        {"InvalidSignature", {.cases = 64, .strict = 4}},
        {"InvalidTypesInSignature", {.cases = 63, .strict = 0}},
        {"ModifiedInteger", {.cases = 5, .strict = 1}},
        {"ModifiedSignature", {.cases = 49, .strict = 5}},
        {"ModularInverse", {.cases = 15, .strict = 15}},
        {"PointDuplication", {.cases = 7, .strict = 7}},
        {"RangeCheck", {.cases = 6, .strict = 0}},
        {"SignatureMalleabilityBitcoin", {.cases = 1, .strict = 1}},
        {"SmallRandS", {.cases = 6, .strict = 6}},
        {"SpecialCaseHash", {.cases = 54, .strict = 54}},
        {"ValidSignature", {.cases = 5, .strict = 5}},
    };
    return expected;
}

void wycheproof() {
    auto const text = test::read_text(WEBCPP_TEST_WYCHEPROOF
                                      "/testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    BOOST_TEST(!ec);
    tallies per_flag;
    tally all;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            decode_case(t, per_flag, all);
        }
    }
    for (auto const& [flag, c] : per_flag) {
        std::cout << "wycheproof " << flag << ": cases=" << c.cases << " strict=" << c.strict
                  << '\n';
    }
    std::cout << "wycheproof all: cases=" << all.cases << " strict=" << all.strict << '\n';
    auto const& expected = expected_tallies();
    BOOST_TEST_EQ(per_flag.size(), expected.size());
    for (auto const& [flag, want] : expected) {
        auto const& got = per_flag[flag];
        if (got.cases != want.cases || got.strict != want.strict) {
            BOOST_ERROR(("counts of flag " + flag + " differ").c_str());
        }
    }
    BOOST_TEST_EQ(all.cases, 464);
    BOOST_TEST_EQ(all.strict, 182);
}

}  // namespace

int main() {
    round_trips();
    to_der_refusals();
    normalization();
    wycheproof();
    return webcpp::test::exit_status(boost::report_errors());
}
