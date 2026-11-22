// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 ECDSA on BearSSL against Wycheproof (spec 8.1): the SHA-256 vectors in the raw form,
// IEEE P1363's r || s, through verify_ecdsa, and in DER through from_der then verify_ecdsa. A
// valid case verifies, an invalid one is refused, and an acceptable one, which neither file has
// at its pinned commit, fails the test so that it is read. The valid cases whose S is high are
// counted: verify_ecdsa accepts both forms, as FIPS 186-5 and WebCrypto do (design D36).

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;
namespace test = webcpp::test;
namespace json = boost::json;

using signature = std::array<std::uint8_t, p256::signature_size>;

json::value load(std::string const& name) {
    auto const text = test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/" + name + ".json");
    boost::system::error_code ec;
    auto value = json::parse(text, ec);
    BOOST_TEST(!ec);
    return value;
}

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

// Reports a case that went wrong, by its file and its number.
void report(std::string const& name, json::value const& t, std::string_view what) {
    std::string message = name;
    message += " tcId ";
    message += std::to_string(t.at("tcId").to_number<std::int64_t>());
    message += ": ";
    message += what;
    BOOST_ERROR(message.c_str());
}

std::array<std::uint8_t, p256::digest_size> sha256(std::span<std::uint8_t const> message) {
    std::array<std::uint8_t, p256::digest_size> out{};
    BOOST_TEST(webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(out, message).has_value());
    return out;
}

// Whether s is above (n - 1) / 2, the half order, compared byte by byte: public values.
bool high_s(signature const& value) {
    static constexpr auto half = crypto::detail::p_curve_traits<crypto::families::p256>::half_order;
    for (std::size_t i = 0; i < half.size(); ++i) {
        if (value[32 + i] != half[i]) {
            return value[32 + i] > half[i];
        }
    }
    return false;
}

// The counts of one file.
struct counts {
    /** Cases read. */
    int total = 0;
    /** Valid cases verified. */
    int valid = 0;
    /** Invalid cases refused. */
    int invalid = 0;
    /** Valid cases whose S is high. */
    int valid_high_s = 0;
};

// One file's cases: `decode` turns a case's signature into the raw form, or refuses it; a valid
// case must decode and verify, an invalid one must be refused at either step.
template <class Decode>
counts run(std::string const& name, Decode decode) {
    auto const doc = load(name);
    counts seen;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const point = test::from_hex(str(group.at("publicKey").at("uncompressed")));
        auto const key = p256::public_key::make(point);
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        for (auto const& t : group.at("tests").as_array()) {
            ++seen.total;
            auto const message = test::from_hex(str(t.at("msg")));
            auto const hash = sha256(message);
            auto const encoded = test::from_hex(str(t.at("sig")));
            auto const decoded = decode(encoded);
            bool const verified =
                decoded.has_value() && p256::verify_ecdsa(*decoded, hash, *key).has_value();
            auto const verdict = str(t.at("result"));
            if (verdict == "valid") {
                ++seen.valid;
                if (!verified) {
                    report(name, t, "valid signature refused");
                } else if (high_s(*decoded)) {
                    ++seen.valid_high_s;
                }
            } else if (verdict == "invalid") {
                ++seen.invalid;
                if (verified) {
                    report(name, t, "invalid signature verified");
                }
            } else {
                // None at the pinned commit: a new one is read before it is classified.
                report(name, t, verdict + ", not expected");
            }
        }
    }
    std::cout << name << ": tests=" << seen.total << " valid_verified=" << seen.valid
              << " invalid_refused=" << seen.invalid << " valid_high_s=" << seen.valid_high_s
              << '\n';
    return seen;
}

void p1363() {
    // A signature of another size than 64 bytes is refused before verify_ecdsa, which takes 64.
    auto const seen =
        run("ecdsa_secp256r1_sha256_p1363_test",
            [](std::vector<std::uint8_t> const& encoded) -> boost::system::result<signature> {
                if (encoded.size() != p256::signature_size) {
                    return crypto::error::invalid_signature;
                }
                signature value{};
                std::ranges::copy(encoded, value.begin());
                return value;
            });
    BOOST_TEST_EQ(seen.total, 262);
    BOOST_TEST_EQ(seen.valid, 173);
    BOOST_TEST_EQ(seen.invalid, 89);
    BOOST_TEST_EQ(seen.valid_high_s, 70);
}

void der() {
    auto const seen =
        run("ecdsa_secp256r1_sha256_test",
            [](std::vector<std::uint8_t> const& encoded) { return p256::from_der(encoded); });
    BOOST_TEST_EQ(seen.total, 484);
    BOOST_TEST_EQ(seen.valid, 174);
    BOOST_TEST_EQ(seen.invalid, 310);
    BOOST_TEST_EQ(seen.valid_high_s, 71);
}

}  // namespace

int main() {
    p1363();
    der();
    return webcpp::test::exit_status(boost::report_errors());
}
