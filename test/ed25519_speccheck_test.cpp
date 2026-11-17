// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The twelve Ed25519 edge cases of Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs"
// (2020), novifinancial/ed25519-speccheck's cases.json, against every Ed25519 backend linked
// (design D31): each backend's raw verdict, its own library called directly, and the verdict of
// curves::ed25519::verify<strict, Backend>, compared with the verdicts committed in
// meta/ed25519_cases.json. Under strict every backend gives libsodium's verdicts. On Emscripten,
// node's WebCrypto verify (Ed25519) gives the row webcrypto-node, an outside view that is compared
// with its committed row but never with strict's. A pin move that changes a verdict fails here
// until the data and the page are regenerated. Each row is printed, so that a first run gives
// the data to review.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten/em_js.h>
#endif

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;
namespace json = boost::json;

#if defined(__EMSCRIPTEN__)
// node's crypto.subtle.verify with an Ed25519 key imported raw: 1 when it accepts, 0 when it
// refuses, 2 when importKey refuses the public key (a refusal of the case too), -1 when verify
// itself throws (the message goes to the console). The inputs are copied before the first await.
// clang-format off
EM_ASYNC_JS(int, subtle_ed25519_verify, (const std::uint8_t* key, const std::uint8_t* msg,
                                         std::size_t msg_size, const std::uint8_t* sig), {
    const key_bytes = HEAPU8.slice(key, key + 32);
    const data = HEAPU8.slice(msg, msg + msg_size);
    const signature = HEAPU8.slice(sig, sig + 64);
    let imported;
    try {
        imported = await globalThis.crypto.subtle.importKey(
            "raw", key_bytes, {name: "Ed25519"}, false, ["verify"]);
    } catch (e) {
        return 2;
    }
    try {
        return (await globalThis.crypto.subtle.verify({name: "Ed25519"}, imported, signature,
                                                      data)) ? 1 : 0;
    } catch (e) {
        console.error("subtle.verify: " + e);
        return -1;
    }
});

// The versions of the node running this program, and of its OpenSSL, on one line.
EM_JS(void, print_node_versions, (), {
    console.log("webcrypto-node run with node " + process.versions.node + ", OpenSSL " +
                process.versions.openssl);
});
// clang-format on
#endif

namespace {

constexpr std::size_t case_count = 12;

using verdicts = std::vector<std::string>;

// One of cases.json's twelve.
struct edge_case {
    std::vector<std::uint8_t> message;
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> signature;
};

std::string text_of(json::value const& value) {
    return std::string(std::string_view(value.as_string()));
}

std::string verdict(bool accepted) {
    return accepted ? "accept" : "reject";
}

// A committed row: twelve verdicts, each accept or reject.
verdicts committed_row(json::value const& row, std::string const& label) {
    verdicts out;
    for (auto const& entry : row.as_array()) {
        out.push_back(text_of(entry));
        if (out.back() != "accept" && out.back() != "reject") {
            BOOST_ERROR(
                (label + ": a committed verdict is neither accept nor reject: " + out.back())
                    .c_str());
        }
    }
    BOOST_TEST_EQ(out.size(), case_count);
    return out;
}

void print_row(std::string const& label, verdicts const& row) {
    std::cout << label << ':';
    for (auto const& entry : row) {
        std::cout << ' ' << entry;
    }
    std::cout << '\n';
}

// The row computed against the row committed, case by case.
void compare(std::string const& label, verdicts const& computed, verdicts const& expected) {
    print_row(label, computed);
    if (computed.size() != expected.size()) {
        BOOST_ERROR((label + ": the committed row has another number of cases").c_str());
        return;
    }
    for (std::size_t index = 0; index < computed.size(); ++index) {
        if (computed[index] != expected[index]) {
            BOOST_ERROR((label + ", case " + std::to_string(index) + ": " + computed[index] +
                         ", committed " + expected[index])
                            .c_str());
        }
    }
}

// libsodium's raw verdicts, crypto_sign_ed25519_verify_detached called directly, and strict's,
// curves::ed25519::verify<strict, backends::sodium>, whose refusal is invalid_signature.
void sodium_rows(std::vector<edge_case> const& cases, verdicts& raw, verdicts& strict) {
    for (auto const& tested : cases) {
        raw.push_back(verdict(crypto_sign_ed25519_verify_detached(
                                  tested.signature.data(), tested.message.data(),
                                  tested.message.size(), tested.public_key.data()) == 0));
        auto const verified = ed25519::verify<ed25519::strict, crypto::backends::sodium>(
            tested.public_key, tested.message, tested.signature);
        if (!verified) {
            BOOST_TEST(verified.error() == crypto::error::invalid_signature);
        }
        strict.push_back(verdict(static_cast<bool>(verified)));
    }
}

}  // namespace

int main() {
    BOOST_TEST(sodium_init() >= 0);
    boost::system::error_code cases_error;
    auto const cases_document =
        json::parse(test::read_file(WEBCPP_TEST_ED25519_SPECCHECK "/cases.json"), cases_error);
    BOOST_TEST(!cases_error);
    boost::system::error_code committed_error;
    auto const committed = json::parse(
        test::read_file(WEBCPP_TEST_CRYPTO_META "/ed25519_cases.json"), committed_error);
    BOOST_TEST(!committed_error);
    if (cases_error || committed_error) {
        return test::exit_status(boost::report_errors());
    }

    std::vector<edge_case> cases;
    for (auto const& entry : cases_document.as_array()) {
        cases.push_back({test::from_hex(text_of(entry.at("message"))),
                         test::from_hex(text_of(entry.at("pub_key"))),
                         test::from_hex(text_of(entry.at("signature")))});
        BOOST_TEST_EQ(cases.back().public_key.size(), 32U);
        BOOST_TEST_EQ(cases.back().signature.size(), 64U);
    }
    BOOST_TEST_EQ(cases.size(), case_count);
    if (cases.size() != case_count) {
        return test::exit_status(boost::report_errors());
    }

    // What each case tests, the page's first column: one text per case.
    BOOST_TEST_EQ(committed.at("cases").as_array().size(), case_count);

    auto const& source = committed.at("source");
    BOOST_TEST_EQ(text_of(source.at("repository")), "novifinancial/ed25519-speccheck");
    BOOST_TEST_EQ(text_of(source.at("commit")), "65519336");
    BOOST_TEST_EQ(text_of(source.at("file")), "cases.json");

    // Every committed backend is one this test runs (libsodium alone in this version), and each
    // backend's strict verdicts are compared with libsodium's committed row: under strict every
    // backend gives libsodium's verdicts.
    auto const& backends = committed.at("backends").as_object();
    BOOST_TEST(backends.contains("sodium"));
    if (!backends.contains("sodium")) {
        return test::exit_status(boost::report_errors());
    }
    auto const sodium_raw = committed_row(backends.at("sodium").at("raw"), "sodium raw");
    auto const sodium_strict = committed_row(backends.at("sodium").at("strict"), "sodium strict");
    // A backend's rows are committed with its run here.
    for (auto const& entry : backends) {
        if (entry.key() != "sodium") {
            BOOST_ERROR(("a committed backend this test does not run: " + std::string(entry.key()))
                            .c_str());
        }
    }

    verdicts raw;
    verdicts strict;
    sodium_rows(cases, raw, strict);
    compare("sodium raw", raw, sodium_raw);
    compare("sodium strict", strict, sodium_strict);

    // The outside view: node's WebCrypto, committed as one row with the node and OpenSSL that
    // gave it.
    auto const* outside = committed.as_object().if_contains("outside");
    BOOST_TEST(outside != nullptr && outside->as_object().size() == 1U &&
               outside->as_object().contains("webcrypto-node"));
    if (outside == nullptr || !outside->as_object().contains("webcrypto-node")) {
        return test::exit_status(boost::report_errors());
    }
    auto const& view = outside->at("webcrypto-node").as_object();
    BOOST_TEST(view.contains("node") && view.at("node").is_string());
    BOOST_TEST(view.contains("openssl") && view.at("openssl").is_string());
    BOOST_TEST(view.contains("verdicts"));
    if (!view.contains("verdicts")) {
        return test::exit_status(boost::report_errors());
    }
    auto const webcrypto = committed_row(view.at("verdicts"), "webcrypto-node");
#if defined(__EMSCRIPTEN__)
    // The versions this run's node has, beside those committed: a node whose row differs says
    // which it is.
    if (view.contains("node") && view.contains("openssl")) {
        std::cout << "webcrypto-node committed with node " << text_of(view.at("node"))
                  << ", OpenSSL " << text_of(view.at("openssl")) << '\n';
    }
    print_node_versions();
    verdicts subtle;
    for (auto const& tested : cases) {
        auto const answer = subtle_ed25519_verify(tested.public_key.data(), tested.message.data(),
                                                  tested.message.size(), tested.signature.data());
        BOOST_TEST(answer >= 0);
        subtle.push_back(verdict(answer == 1));
    }
    compare("webcrypto-node", subtle, webcrypto);
#else
    static_cast<void>(webcrypto);
#endif

    std::cout << "ed25519 speccheck: cases=" << cases.size() << '\n';
    return test::exit_status(boost::report_errors());
}
