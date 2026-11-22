// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The twelve Ed25519 edge cases of Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs"
// (2020), novifinancial/ed25519-speccheck's cases.json, against every Ed25519 backend linked
// (design D31): each backend's raw verdict, its own library called directly, and the verdict of
// crypto::verify<Backend>(crypto::eddsa, ..., strict), compared with the verdicts committed in
// meta/ed25519_cases.json. Under strict every backend gives libsodium's verdicts. On Emscripten,
// node's WebCrypto verify (Ed25519) gives the row webcrypto-node, an outside view that is compared
// with its committed row but never with strict's. A pin move that changes a verdict fails here
// until the data and the page are regenerated. Each row is printed, so that a first run gives
// the data to review.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>

#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/em_js.h>
#endif

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace test = webcpp::test;
namespace json = boost::json;

#ifdef __EMSCRIPTEN__
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

// The null value a missing key reads as, which every reader below reports as of another shape.
json::value const missing_value;

// The value key names in parent, or the null value when it holds none.
json::value const& value_at(json::object const& parent, std::string_view key) noexcept {
    auto const* found = parent.if_contains(key);
    return found == nullptr ? missing_value : *found;
}

// The text of value, or an empty text and a failed test when it is no string: a committed or
// upstream file of another shape fails the test rather than end it on an exception.
std::string text_of(json::value const& value, std::string_view label) {
    auto const* text = value.if_string();
    if (text == nullptr) {
        BOOST_ERROR((std::string(label) + " is no string").c_str());
        return {};
    }
    return std::string(std::string_view(*text));
}

// The text key names in parent (see text_of).
std::string text_at(json::object const& parent, std::string_view key) {
    return text_of(value_at(parent, key), key);
}

std::string_view verdict(bool accepted) {
    return accepted ? "accept" : "reject";
}

// A committed row: twelve verdicts, each accept or reject. A row of another shape fails the test,
// rather than end it on an exception.
verdicts committed_row(json::value const& row, std::string const& label) {
    verdicts out;
    auto const* entries = row.if_array();
    if (entries == nullptr) {
        BOOST_ERROR((label + ": the committed row is no array").c_str());
        return out;
    }
    for (auto const& entry : *entries) {
        auto const* text = entry.if_string();
        out.emplace_back(text == nullptr ? "(not a string)" : std::string_view(*text));
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
// crypto::verify<backends::sodium>(crypto::eddsa, ..., strict), whose refusal is
// invalid_signature.
void sodium_rows(std::vector<edge_case> const& cases, verdicts& raw, verdicts& strict) {
    for (auto const& tested : cases) {
        raw.emplace_back(verdict(crypto_sign_ed25519_verify_detached(
                                     tested.signature.data(), tested.message.data(),
                                     tested.message.size(), tested.public_key.data()) == 0));
        auto const verified = crypto::verify<crypto::backends::sodium>(
            crypto::eddsa, tested.signature, tested.message, tested.public_key, ed25519::strict);
        if (!verified) {
            BOOST_TEST(verified.error() == crypto::error::invalid_signature);
        }
        strict.emplace_back(verdict(static_cast<bool>(verified)));
    }
}

// The object key names in parent; null when parent holds no key, or another kind of value there.
json::object const* object_in(json::object const& parent, std::string_view key) noexcept {
    auto const* found = parent.if_contains(key);
    return found == nullptr ? nullptr : found->if_object();
}

// The upstream file's cases; none when the file or an entry is of another shape, which fails
// the test, or when it holds another count of cases.
std::optional<std::vector<edge_case>> upstream_cases(json::value const& document) {
    auto const* entries = document.if_array();
    BOOST_TEST(entries != nullptr);
    if (entries == nullptr) {
        return std::nullopt;
    }
    std::vector<edge_case> cases;
    for (auto const& entry : *entries) {
        auto const* fields = entry.if_object();
        BOOST_TEST(fields != nullptr);
        if (fields == nullptr) {
            return std::nullopt;
        }
        cases.push_back({
            .message = test::from_hex(text_at(*fields, "message")),
            .public_key = test::from_hex(text_at(*fields, "pub_key")),
            .signature = test::from_hex(text_at(*fields, "signature")),
        });
        BOOST_TEST_EQ(cases.back().public_key.size(), 32U);
        BOOST_TEST_EQ(cases.back().signature.size(), 64U);
    }
    BOOST_TEST_EQ(cases.size(), case_count);
    if (cases.size() != case_count) {
        return std::nullopt;
    }
    return cases;
}

// The outside view: node's WebCrypto, committed as one row with the node and OpenSSL that
// gave it. A view of another shape fails the test, rather than end it on an exception.
// False when the view is missing; its verdicts are compared under Emscripten alone, with node.
bool outside_agrees(json::object const& root, std::vector<edge_case> const& cases) {
    auto const* outside = object_in(root, "outside");
    auto const* view = outside == nullptr ? nullptr : object_in(*outside, "webcrypto-node");
    BOOST_TEST(outside != nullptr && outside->size() == 1U && view != nullptr);
    if (view == nullptr) {
        return false;
    }
    BOOST_TEST(value_at(*view, "node").is_string());
    BOOST_TEST(value_at(*view, "openssl").is_string());
    BOOST_TEST(view->contains("verdicts"));
    if (!view->contains("verdicts")) {
        return false;
    }
    auto const webcrypto = committed_row(value_at(*view, "verdicts"), "webcrypto-node");
#ifdef __EMSCRIPTEN__
    // The versions this run's node has, beside those committed: a node whose row differs says
    // which it is.
    if (value_at(*view, "node").is_string() && value_at(*view, "openssl").is_string()) {
        std::cout << "webcrypto-node committed with node " << text_at(*view, "node") << ", OpenSSL "
                  << text_at(*view, "openssl") << '\n';
    }
    print_node_versions();
    verdicts subtle;
    for (auto const& tested : cases) {
        auto const answer = subtle_ed25519_verify(tested.public_key.data(), tested.message.data(),
                                                  tested.message.size(), tested.signature.data());
        BOOST_TEST(answer >= 0);
        subtle.emplace_back(verdict(answer == 1));
    }
    compare("webcrypto-node", subtle, webcrypto);
#else
    static_cast<void>(webcrypto);
    static_cast<void>(cases);
#endif
    return true;
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

    auto const read = upstream_cases(cases_document);
    if (!read) {
        return test::exit_status(boost::report_errors());
    }
    std::vector<edge_case> const& cases = *read;

    // The committed file: each part of another shape fails the test, rather than end it on an
    // exception.
    auto const* root = committed.if_object();
    BOOST_TEST(root != nullptr);
    if (root == nullptr) {
        return test::exit_status(boost::report_errors());
    }

    // What each case tests, the page's first column: one text per case.
    auto const* texts = value_at(*root, "cases").if_array();
    BOOST_TEST(texts != nullptr && texts->size() == case_count);

    auto const* source = object_in(*root, "source");
    BOOST_TEST(source != nullptr);
    if (source != nullptr) {
        BOOST_TEST_EQ(text_at(*source, "repository"), "novifinancial/ed25519-speccheck");
        BOOST_TEST_EQ(text_at(*source, "commit"), "65519336");
        BOOST_TEST_EQ(text_at(*source, "file"), "cases.json");
    }

    // Every committed backend is one this test runs (libsodium alone in this version), and each
    // backend's strict verdicts are compared with libsodium's committed row: under strict every
    // backend gives libsodium's verdicts.
    auto const* backends = object_in(*root, "backends");
    auto const* sodium = backends == nullptr ? nullptr : object_in(*backends, "sodium");
    BOOST_TEST(sodium != nullptr);
    if (sodium == nullptr) {
        return test::exit_status(boost::report_errors());
    }
    auto const sodium_raw = committed_row(value_at(*sodium, "raw"), "sodium raw");
    auto const sodium_strict = committed_row(value_at(*sodium, "strict"), "sodium strict");
    // A backend's rows are committed with its run here.
    for (auto const& entry : *backends) {
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

    if (!outside_agrees(*root, cases)) {
        return test::exit_status(boost::report_errors());
    }

    std::cout << "ed25519 speccheck: cases=" << cases.size() << '\n';
    return test::exit_status(boost::report_errors());
}
