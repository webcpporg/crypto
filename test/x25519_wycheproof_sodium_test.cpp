// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// X25519 against Wycheproof's file (testvectors_v1/x25519_test.json) through curves::x25519::agree
// on libsodium, every case: each shared secret Wycheproof gives, except the all-zero ones (keys of
// low order), which libsodium refuses and agree reports as weak_public_key (design D8). A
// disagreement is reported, never listed away.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

std::string text_of(json::value const& value) {
    return std::string(std::string_view(value.as_string()));
}

/** What one case gave: an agreed secret, a refused weak one, or a verdict not known. */
enum class outcome { agreed, weak, unknown };

/** Runs one case, reporting a disagreement under its tcId. */
outcome run_case(json::value const& tested) {
    auto const secret_key = test::from_hex(text_of(tested.at("private")));
    auto const peer_key = test::from_hex(text_of(tested.at("public")));
    auto const expected = test::from_hex(text_of(tested.at("shared")));
    auto const verdict = text_of(tested.at("result"));
    auto label = "tcId " + std::to_string(tested.at("tcId").to_number<std::int64_t>());
    if (verdict != "valid" && verdict != "acceptable") {
        BOOST_ERROR(((label += ": the verdict ") += verdict).c_str());
        return outcome::unknown;
    }
    auto const shared = x25519::agree(secret_key, peer_key);
    if (std::ranges::all_of(expected, [](std::uint8_t byte) { return byte == 0; })) {
        if (shared || shared.error() != crypto::error::weak_public_key) {
            BOOST_ERROR((label += ": an all-zero secret not refused as weak_public_key").c_str());
        }
        return outcome::weak;
    }
    if (!shared || !std::ranges::equal(shared->bytes(), expected)) {
        BOOST_ERROR((label += ": not Wycheproof's shared secret").c_str());
    }
    return outcome::agreed;
}

}  // namespace

int main() {
    auto const document_text =
        test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/x25519_test.json");
    boost::system::error_code parse_error;
    auto const document = json::parse(document_text, parse_error);
    BOOST_TEST(!parse_error);
    if (parse_error) {
        return test::exit_status(boost::report_errors());
    }
    int total = 0;
    int agreed = 0;
    int weak = 0;
    for (auto const& group : document.at("testGroups").as_array()) {
        BOOST_TEST(text_of(group.at("curve")) == "curve25519");
        for (auto const& tested : group.at("tests").as_array()) {
            ++total;
            auto const result = run_case(tested);
            agreed += result == outcome::agreed ? 1 : 0;
            weak += result == outcome::weak ? 1 : 0;
        }
    }
    std::cout << "x25519 wycheproof: tests=" << total << " agreed=" << agreed << " weak=" << weak
              << '\n';
    BOOST_TEST_EQ(total, 518);
    BOOST_TEST_EQ(agreed, 487);
    BOOST_TEST_EQ(weak, 31);
    return test::exit_status(boost::report_errors());
}
