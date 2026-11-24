// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519 against Wycheproof's EdDSA file (testvectors_v1/ed25519_test.json) through
// crypto::verify(crypto::eddsa, ...) on libsodium, strict: every valid case accepted and every
// invalid case refused with invalid_signature, without exception (a disagreement is reported, never
// listed away).

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>
#include <boost/system/result.hpp>

#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

std::string text_of(json::value const& value) {
    return std::string(std::string_view(value.as_string()));
}

// A case's signature verified: a signature of another size is no signature, refused by
// from_bytes before any verify.
boost::system::result<void> verified_case(std::span<std::uint8_t const> signature_bytes,
                                          std::span<std::uint8_t const> message,
                                          ed25519::public_key const& public_key) {
    auto const made = ed25519::signature::from_bytes(signature_bytes);
    if (!made) {
        return made.error();
    }
    return crypto::verify(crypto::eddsa, *made, message, public_key);
}

}  // namespace

int main() {
    auto const document_text =
        test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/ed25519_test.json");
    boost::system::error_code parse_error;
    auto const document = json::parse(document_text, parse_error);
    BOOST_TEST(!parse_error);
    if (parse_error) {
        return test::exit_status(boost::report_errors());
    }
    int total = 0;
    int accepted = 0;
    int refused = 0;
    for (auto const& group : document.at("testGroups").as_array()) {
        // Every group's key is 32 bytes: made, whatever its point (design R16).
        auto const public_key = ed25519::public_key::from_bytes(
            test::from_hex(text_of(group.at("publicKey").at("pk"))));
        BOOST_TEST(public_key.has_value());
        if (!public_key) {
            continue;
        }
        for (auto const& tested : group.at("tests").as_array()) {
            ++total;
            auto const message = test::from_hex(text_of(tested.at("msg")));
            auto const signature = test::from_hex(text_of(tested.at("sig")));
            auto const verdict = text_of(tested.at("result"));
            auto const verified = verified_case(signature, message, *public_key);
            auto label = "tcId " + std::to_string(tested.at("tcId").to_number<std::int64_t>());
            if (verdict == "valid") {
                ++accepted;
                if (!verified) {
                    BOOST_ERROR((label += ": a valid signature refused").c_str());
                }
            } else if (verdict == "invalid") {
                ++refused;
                if (verified || verified.error() != crypto::error::invalid_signature) {
                    BOOST_ERROR((label += ": an invalid signature not refused as invalid_signature")
                                    .c_str());
                }
            } else {
                BOOST_ERROR(((label += ": the verdict ") += verdict).c_str());
            }
        }
    }
    std::cout << "ed25519 wycheproof: tests=" << total << " valid=" << accepted
              << " invalid=" << refused << '\n';
    BOOST_TEST_EQ(total, 151);
    BOOST_TEST_EQ(accepted, 88);
    BOOST_TEST_EQ(refused, 63);
    return test::exit_status(boost::report_errors());
}
