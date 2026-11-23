// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256 ECDSA on BearSSL against Wycheproof (spec 8.1): the SHA-256 vectors in the raw form,
// IEEE P1363's r || s, through crypto::verify(ecdsa_sha256, ...), and in DER through from_der
// then crypto::verify, each case verified from its message and from its digest, with the same
// verdict. A valid case verifies, an invalid one is refused, and an acceptable one, which neither
// file has at its pinned commit, fails the test so that it is read. The valid cases whose S is
// high (is_low_s false) are counted: crypto::verify accepts both forms, as FIPS 186-5 and
// WebCrypto do (design D36).

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

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

using signature = p256::ecdsa_signature;

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

// Whether a signature verifies, from the message and from its digest: a case whose two verdicts
// differ is reported.
bool verified_both_ways(std::string const& name, json::value const& t, signature const& value,
                        std::span<std::uint8_t const> message, p256::public_key const& key) {
    bool const verified = crypto::verify(crypto::ecdsa_sha256, value, message, key).has_value();
    bool const verified_digest =
        crypto::verify(crypto::ecdsa_sha256, value, crypto::prehashed{sha256(message)}, key)
            .has_value();
    if (verified != verified_digest) {
        report(name, t, "message and digest verified differently");
    }
    return verified;
}

// One file's cases: `decode` turns a case's signature into its type, or refuses it; a valid
// case must decode and verify, an invalid one must be refused at either step.
template <class Decode>
counts run(std::string const& name, Decode decode) {
    auto const doc = load(name);
    counts seen;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const point = test::from_hex(str(group.at("publicKey").at("uncompressed")));
        auto const key = p256::public_key::from_bytes(point);
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        for (auto const& t : group.at("tests").as_array()) {
            ++seen.total;
            auto const message = test::from_hex(str(t.at("msg")));
            auto const decoded = decode(test::from_hex(str(t.at("sig"))));
            bool const verified =
                decoded.has_value() && verified_both_ways(name, t, *decoded, message, *key);
            auto const verdict = str(t.at("result"));
            if (verdict == "valid") {
                ++seen.valid;
                if (!verified) {
                    report(name, t, "valid signature refused");
                } else if (!p256::is_low_s(*decoded)) {
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
    // A signature of another size than 64 bytes is refused by from_bytes, before crypto::verify,
    // which takes the type.
    auto const seen = run(
        "ecdsa_secp256r1_sha256_p1363_test",
        [](std::vector<std::uint8_t> const& encoded) { return signature::from_bytes(encoded); });
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
