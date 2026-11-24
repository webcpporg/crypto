// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's MuSig2 against BIP 327's vectors (bip-0327/vectors/*.json). key_sort: sorting the
// six parsed keys with public_key's order gives sorted_pubkeys. key_agg: the 4 valid cases'
// x-only keys; its error cases, three keys public_key::from_bytes refuses and two tweaks the
// aggregate key refuses, after which the key is unchanged. nonce_agg: the 2 valid sums (the second
// at infinity, written as 33 zero bytes) and 3 nonces parse_public_nonce refuses. sign_verify: the
// 4 valid cases whose message is 32 bytes verify their partial signature (the empty and the
// 38-byte message are counted as skipped: libsecp256k1 signs 32-byte messages); the 3
// verify_fail cases, over the aggregate of their nonces, do not; the verify_error and sign_error
// cases that need no secret nonce of the vector's are refused at parsing (a sign_error case that
// needs one is counted as skipped). tweak: the 5 valid cases verify after their tweaks, the
// error case's tweak is refused. sig_agg: the 4 valid cases give the vector's signature, which
// crypto::verify(crypto::schnorr, ...) accepts under the aggregate key, and a partial signature not
// below the group order is refused. The vectors' secret nonces (sign_verify's and tweak's
// secnonces, det_sign_vectors.json, nonce_gen_vectors.json) are not reachable through crypto's
// interface by design: a secret_nonce exists only from generate_nonce, with fresh randomness;
// libsecp256k1's own tests run them in the c-suites lane. Round trips: 2-of-2 and 3-of-3 over
// seeded key pairs and messages, plain and with an x-only tweak, each partial signature verified,
// the aggregate verified with crypto::verify(crypto::schnorr, ...), and a partial signature changed
// in one bit refused. The nonce: consumed by partial_sign, refused when used again or given to
// another key pair. The refusals of a moved-from key pair, of sizes and of workspaces; every
// workspace is zero afterwards.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_checks.hpp"
#include "support/test_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <numeric>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace musig = webcpp::crypto::curves::secp256k1::musig;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using bytes = std::vector<std::uint8_t>;
using scalar = std::array<std::uint8_t, 32>;

// Each type libsecp256k1 checks the magic of is made only by the functions that return one.
static_assert(!std::is_default_constructible_v<musig::aggregate_key>);
static_assert(!std::is_default_constructible_v<musig::public_nonce>);
static_assert(!std::is_default_constructible_v<musig::aggregate_nonce>);
static_assert(!std::is_default_constructible_v<musig::session>);
static_assert(!std::is_default_constructible_v<musig::partial_signature>);
static_assert(!std::is_default_constructible_v<musig::secret_nonce>);
// The public forms are copied freely; the secret nonce is moved, never copied.
static_assert(std::is_copy_constructible_v<musig::aggregate_key>);
static_assert(std::is_copy_constructible_v<musig::public_nonce>);
static_assert(std::is_copy_constructible_v<musig::aggregate_nonce>);
static_assert(std::is_copy_constructible_v<musig::session>);
static_assert(std::is_copy_constructible_v<musig::partial_signature>);
static_assert(!std::is_copy_constructible_v<musig::secret_nonce>);
static_assert(!std::is_copy_assignable_v<musig::secret_nonce>);
static_assert(std::is_nothrow_move_constructible_v<musig::secret_nonce>);
static_assert(std::is_nothrow_move_assignable_v<musig::secret_nonce>);
static_assert(musig::public_nonce_size == 66);
static_assert(musig::aggregate_nonce_size == 66);
static_assert(musig::partial_signature_size == 32);
static_assert(musig::workspace_size(3) == (3 * sizeof(void const*)) + alignof(std::max_align_t));

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

bytes hex(json::value const& v) {
    return test::from_hex(str(v));
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(json::value const& v) {
    auto const b = hex(v);
    std::array<std::uint8_t, N> out{};
    if (BOOST_TEST_EQ(b.size(), N)) {
        std::ranges::copy(b, out.begin());
    }
    return out;
}

json::value document(char const* name) {
    auto const text = test::read_file(std::string(WEBCPP_TEST_BIPS "/bip-0327/vectors/") + name);
    boost::system::error_code ec;
    auto doc = json::parse(text, ec);
    if (ec) {
        BOOST_ERROR(name);
        std::exit(boost::report_errors());
    }
    return doc;
}

std::size_t index_at(json::array const& indices, std::size_t at) {
    return static_cast<std::size_t>(indices.at(at).as_int64());
}

// A workspace on the heap, filled with non-zero bytes, so that its wipe is seen.
std::vector<std::byte> lent(std::size_t count) {
    return std::vector<std::byte>(musig::workspace_size(count), std::byte{0xa5});
}

bool all_zero(std::span<std::byte const> space) {
    return std::ranges::all_of(space, [](std::byte b) { return b == std::byte{0}; });
}

secp::public_key parsed_key(json::value const& v) {
    auto const parsed = secp::public_key::from_bytes(hex(v));
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

// The keys at `indices` of `keys`, parsed.
std::vector<secp::public_key> keys_at(json::array const& keys, json::array const& indices) {
    std::vector<secp::public_key> out;
    for (auto const& i : indices) {
        out.push_back(parsed_key(keys.at(static_cast<std::size_t>(i.as_int64()))));
    }
    return out;
}

musig::aggregate_key aggregated(std::span<secp::public_key const> keys) {
    auto space = lent(keys.size());
    auto made = musig::key_aggregate(keys, space);
    BOOST_TEST(all_zero(space));
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return *made;
}

musig::public_nonce parsed_nonce(json::value const& v) {
    auto const parsed = musig::parse_public_nonce(hex(v));
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

musig::aggregate_nonce parsed_aggregate(json::value const& v) {
    auto const parsed = musig::parse_aggregate_nonce(hex(v));
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

musig::partial_signature parsed_signature(json::value const& v) {
    auto const parsed = musig::parse_partial_signature(hex(v));
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

musig::session session_of(musig::aggregate_nonce const& nonce_sum, scalar const& message,
                          musig::aggregate_key const& key) {
    auto made = musig::nonce_process(nonce_sum, message, key);
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return *made;
}

// Applies a case's tweaks to `key` in order: x-only or plain, as `is_xonly` says.
boost::system::result<void> tweaked(musig::aggregate_key& key, json::array const& tweaks,
                                    json::array const& tweak_indices, json::array const& is_xonly) {
    for (std::size_t i = 0; i < tweak_indices.size(); ++i) {
        auto const tweak = fixed<32>(tweaks.at(index_at(tweak_indices, i)));
        auto const done =
            is_xonly.at(i).as_bool() ? key.tweak_xonly_add(tweak) : key.tweak_add(tweak);
        if (!done) {
            return done;
        }
    }
    return {};
}

void key_sort() {
    auto const doc = document("key_sort_vectors.json");
    std::vector<secp::public_key> keys;
    for (auto const& k : doc.at("pubkeys").as_array()) {
        keys.push_back(parsed_key(k));
    }
    std::ranges::sort(keys);
    auto const& sorted = doc.at("sorted_pubkeys").as_array();
    if (!BOOST_TEST_EQ(keys.size(), sorted.size())) {
        return;
    }
    for (std::size_t i = 0; i < keys.size(); ++i) {
        BOOST_TEST(std::ranges::equal(keys[i].compressed(), hex(sorted.at(i))));
    }
    std::cout << "key_sort: keys=" << keys.size() << '\n';
}

void key_agg() {
    auto const doc = document("key_agg_vectors.json");
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& tweaks = doc.at("tweaks").as_array();
    int valid = 0;
    for (auto const& c : doc.at("valid_test_cases").as_array()) {
        auto const signers = keys_at(keys, c.at("key_indices").as_array());
        auto const key = aggregated(signers);
        valid += static_cast<int>(
            BOOST_TEST(std::ranges::equal(key.xonly_public_key(), hex(c.at("expected")))));
    }
    int refused = 0;
    for (auto const& c : doc.at("error_test_cases").as_array()) {
        auto const& indices = c.at("key_indices").as_array();
        auto const& error = c.at("error").as_object();
        if (error.at("type").as_string() == "invalid_contribution") {
            // The signer's key does not parse.
            auto const bad =
                index_at(indices, static_cast<std::size_t>(error.at("signer").as_int64()));
            refused += static_cast<int>(
                BOOST_TEST(secp::public_key::from_bytes(hex(keys.at(bad))).error() ==
                           crypto::error::invalid_public_key));
            continue;
        }
        // A tweak not below the group order, or one that gives the point at infinity: refused,
        // and the key is as it was.
        auto key = aggregated(keys_at(keys, indices));
        auto const& tweak_indices = c.at("tweak_indices").as_array();
        auto const& is_xonly = c.at("is_xonly").as_array();
        auto const before = key.xonly_public_key();
        auto const done = tweaked(key, tweaks, tweak_indices, is_xonly);
        refused += static_cast<int>(BOOST_TEST(done.error() == crypto::error::invalid_secret_key));
        BOOST_TEST(key.xonly_public_key() == before);
    }
    std::cout << "key_agg: valid=" << valid << " refused=" << refused << '\n';
    BOOST_TEST_EQ(valid, 4);
    BOOST_TEST_EQ(refused, 5);
}

void nonce_agg() {
    auto const doc = document("nonce_agg_vectors.json");
    auto const& nonces = doc.at("pnonces").as_array();
    int valid = 0;
    for (auto const& c : doc.at("valid_test_cases").as_array()) {
        std::vector<musig::public_nonce> signer_nonces;
        for (auto const& i : c.at("pnonce_indices").as_array()) {
            signer_nonces.push_back(
                parsed_nonce(nonces.at(static_cast<std::size_t>(i.as_int64()))));
            // Each nonce is written back as it was read.
            BOOST_TEST(std::ranges::equal(musig::serialize_public_nonce(signer_nonces.back()),
                                          hex(nonces.at(static_cast<std::size_t>(i.as_int64())))));
        }
        auto space = lent(signer_nonces.size());
        auto const sum = musig::nonce_aggregate(signer_nonces, space);
        BOOST_TEST(all_zero(space));
        if (BOOST_TEST(sum.has_value())) {
            auto const written = musig::serialize_aggregate_nonce(*sum);
            valid +=
                static_cast<int>(BOOST_TEST(std::ranges::equal(written, hex(c.at("expected")))));
            // And the sum, parsed back, is written the same: the point at infinity included.
            auto const again = musig::parse_aggregate_nonce(written);
            BOOST_TEST(again && musig::serialize_aggregate_nonce(*again) == written);
        }
    }
    int refused = 0;
    for (auto const& c : doc.at("error_test_cases").as_array()) {
        auto const& indices = c.at("pnonce_indices").as_array();
        auto const bad =
            index_at(indices, static_cast<std::size_t>(c.at("error").at("signer").as_int64()));
        refused +=
            static_cast<int>(BOOST_TEST(musig::parse_public_nonce(hex(nonces.at(bad))).error() ==
                                        crypto::error::invalid_point));
    }
    std::cout << "nonce_agg: valid=" << valid << " refused=" << refused << '\n';
    BOOST_TEST_EQ(valid, 2);
    BOOST_TEST_EQ(refused, 3);
}

// sign_verify's valid cases: each partial signature is the vector's and verifies.
int sign_verify_valid(json::value const& doc, int& skipped) {
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& nonces = doc.at("pnonces").as_array();
    auto const& sums = doc.at("aggnonces").as_array();
    auto const& messages = doc.at("msgs").as_array();
    int verified = 0;
    for (auto const& c : doc.at("valid_test_cases").as_array()) {
        auto const message =
            hex(messages.at(static_cast<std::size_t>(c.at("msg_index").as_int64())));
        if (message.size() != 32) {
            ++skipped;
            continue;
        }
        auto const signers = keys_at(keys, c.at("key_indices").as_array());
        auto const key = aggregated(signers);
        auto const sum =
            parsed_aggregate(sums.at(static_cast<std::size_t>(c.at("aggnonce_index").as_int64())));
        scalar message32{};
        std::ranges::copy(message, message32.begin());
        auto const signing_session = session_of(sum, message32, key);
        auto const signer = static_cast<std::size_t>(c.at("signer_index").as_int64());
        auto const signer_nonce =
            parsed_nonce(nonces.at(index_at(c.at("nonce_indices").as_array(), signer)));
        auto const part = parsed_signature(c.at("expected"));
        BOOST_TEST(musig::serialize_partial_signature(part) == fixed<32>(c.at("expected")));
        verified += static_cast<int>(
            BOOST_TEST(musig::partial_signature_verify(part, signer_nonce, signers[signer], key,
                                                       signing_session)
                           .has_value()));
    }
    return verified;
}

// verify_fail: the cases carry no aggregate nonce; the session's is the sum of their nonces.
int sign_verify_failures(json::value const& doc) {
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& nonces = doc.at("pnonces").as_array();
    auto const& messages = doc.at("msgs").as_array();
    int failed = 0;
    for (auto const& c : doc.at("verify_fail_test_cases").as_array()) {
        auto const parsed = musig::parse_partial_signature(hex(c.at("sig")));
        if (!parsed) {
            // A partial signature not below the group order.
            failed +=
                static_cast<int>(BOOST_TEST(parsed.error() == crypto::error::invalid_signature));
            continue;
        }
        auto const signers = keys_at(keys, c.at("key_indices").as_array());
        auto const key = aggregated(signers);
        std::vector<musig::public_nonce> signer_nonces;
        for (auto const& i : c.at("nonce_indices").as_array()) {
            signer_nonces.push_back(
                parsed_nonce(nonces.at(static_cast<std::size_t>(i.as_int64()))));
        }
        auto space = lent(signer_nonces.size());
        auto const sum = musig::nonce_aggregate(signer_nonces, space);
        if (!BOOST_TEST(sum.has_value())) {
            continue;
        }
        auto const message32 =
            fixed<32>(messages.at(static_cast<std::size_t>(c.at("msg_index").as_int64())));
        auto const signing_session = session_of(*sum, message32, key);
        auto const signer = static_cast<std::size_t>(c.at("signer_index").as_int64());
        failed += static_cast<int>(
            BOOST_TEST(musig::partial_signature_verify(*parsed, signer_nonces[signer],
                                                       signers[signer], key, signing_session)
                           .error() == crypto::error::invalid_signature));
    }
    return failed;
}

// verify_error: a nonce or a key that does not parse.
int sign_verify_errors(json::value const& doc) {
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& nonces = doc.at("pnonces").as_array();
    int refused = 0;
    for (auto const& c : doc.at("verify_error_test_cases").as_array()) {
        auto const& error = c.at("error").as_object();
        auto const signer = static_cast<std::size_t>(error.at("signer").as_int64());
        if (error.at("contrib").as_string() == "pubnonce") {
            auto const bad = index_at(c.at("nonce_indices").as_array(), signer);
            refused += static_cast<int>(
                BOOST_TEST(musig::parse_public_nonce(hex(nonces.at(bad))).error() ==
                           crypto::error::invalid_point));
        } else {
            auto const bad = index_at(c.at("key_indices").as_array(), signer);
            refused += static_cast<int>(
                BOOST_TEST(secp::public_key::from_bytes(hex(keys.at(bad))).error() ==
                           crypto::error::invalid_public_key));
        }
    }
    return refused;
}

// sign_error: the cases that need no secret nonce of the vector's are refused at parsing.
int sign_errors(json::value const& doc, int& skipped) {
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& sums = doc.at("aggnonces").as_array();
    int refused = 0;
    for (auto const& c : doc.at("sign_error_test_cases").as_array()) {
        auto const& error = c.at("error").as_object();
        if (error.at("type").as_string() != "invalid_contribution") {
            ++skipped;
            continue;
        }
        if (error.at("contrib").as_string() == "aggnonce") {
            auto const bad = static_cast<std::size_t>(c.at("aggnonce_index").as_int64());
            refused += static_cast<int>(
                BOOST_TEST(musig::parse_aggregate_nonce(hex(sums.at(bad))).error() ==
                           crypto::error::invalid_point));
        } else {
            auto const bad = index_at(c.at("key_indices").as_array(),
                                      static_cast<std::size_t>(error.at("signer").as_int64()));
            refused += static_cast<int>(
                BOOST_TEST(secp::public_key::from_bytes(hex(keys.at(bad))).error() ==
                           crypto::error::invalid_public_key));
        }
    }
    return refused;
}

void sign_verify() {
    auto const doc = document("sign_verify_vectors.json");
    int skipped = 0;
    int const verified = sign_verify_valid(doc, skipped);
    int const failed = sign_verify_failures(doc);
    int const refused = sign_verify_errors(doc);
    int sign_skipped = 0;
    int const sign_refused = sign_errors(doc, sign_skipped);
    std::cout << "sign_verify: verified=" << verified << " skipped=" << skipped
              << " verify_fail=" << failed << " verify_error=" << refused
              << " sign_error=" << sign_refused << " sign_error_skipped=" << sign_skipped << '\n';
    BOOST_TEST_EQ(verified, 4);
    BOOST_TEST_EQ(skipped, 2);
    BOOST_TEST_EQ(failed, 3);
    BOOST_TEST_EQ(refused, 2);
    BOOST_TEST_EQ(sign_refused, 4);
    BOOST_TEST_EQ(sign_skipped, 2);
}

void tweak() {
    auto const doc = document("tweak_vectors.json");
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& nonces = doc.at("pnonces").as_array();
    auto const& tweaks = doc.at("tweaks").as_array();
    auto const sum = parsed_aggregate(doc.at("aggnonce"));
    auto const message = fixed<32>(doc.at("msg"));
    int verified = 0;
    for (auto const& c : doc.at("valid_test_cases").as_array()) {
        auto const signers = keys_at(keys, c.at("key_indices").as_array());
        auto key = aggregated(signers);
        if (!BOOST_TEST(
                tweaked(key, tweaks, c.at("tweak_indices").as_array(), c.at("is_xonly").as_array())
                    .has_value())) {
            continue;
        }
        auto const signing_session = session_of(sum, message, key);
        auto const signer = static_cast<std::size_t>(c.at("signer_index").as_int64());
        auto const signer_nonce =
            parsed_nonce(nonces.at(index_at(c.at("nonce_indices").as_array(), signer)));
        verified += static_cast<int>(BOOST_TEST(
            musig::partial_signature_verify(parsed_signature(c.at("expected")), signer_nonce,
                                            signers[signer], key, signing_session)
                .has_value()));
    }
    int refused = 0;
    for (auto const& c : doc.at("error_test_cases").as_array()) {
        auto key = aggregated(keys_at(keys, c.at("key_indices").as_array()));
        auto const before = key.full_public_key();
        auto const done =
            tweaked(key, tweaks, c.at("tweak_indices").as_array(), c.at("is_xonly").as_array());
        refused += static_cast<int>(BOOST_TEST(done.error() == crypto::error::invalid_secret_key));
        BOOST_TEST(key.full_public_key() == before);
    }
    std::cout << "tweak: verified=" << verified << " refused=" << refused << '\n';
    BOOST_TEST_EQ(verified, 5);
    BOOST_TEST_EQ(refused, 1);
}

void sig_agg() {
    auto const doc = document("sig_agg_vectors.json");
    auto const& keys = doc.at("pubkeys").as_array();
    auto const& tweaks = doc.at("tweaks").as_array();
    auto const& parts = doc.at("psigs").as_array();
    auto const message = fixed<32>(doc.at("msg"));
    int aggregated_count = 0;
    for (auto const& c : doc.at("valid_test_cases").as_array()) {
        auto key = aggregated(keys_at(keys, c.at("key_indices").as_array()));
        if (!BOOST_TEST(
                tweaked(key, tweaks, c.at("tweak_indices").as_array(), c.at("is_xonly").as_array())
                    .has_value())) {
            continue;
        }
        auto const signing_session = session_of(parsed_aggregate(c.at("aggnonce")), message, key);
        std::vector<musig::partial_signature> signature_parts;
        for (auto const& i : c.at("psig_indices").as_array()) {
            signature_parts.push_back(
                parsed_signature(parts.at(static_cast<std::size_t>(i.as_int64()))));
        }
        auto space = lent(signature_parts.size());
        auto const signature =
            musig::partial_signature_aggregate(signing_session, signature_parts, space);
        BOOST_TEST(all_zero(space));
        if (!BOOST_TEST(signature.has_value())) {
            continue;
        }
        BOOST_TEST(std::ranges::equal(signature->bytes(), hex(c.at("expected"))));
        aggregated_count += static_cast<int>(
            BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, key.xonly_public_key())
                           .has_value()));
    }
    int refused = 0;
    for (auto const& c : doc.at("error_test_cases").as_array()) {
        auto const& indices = c.at("psig_indices").as_array();
        auto const bad =
            index_at(indices, static_cast<std::size_t>(c.at("error").at("signer").as_int64()));
        refused += static_cast<int>(
            BOOST_TEST(musig::parse_partial_signature(hex(parts.at(bad))).error() ==
                       crypto::error::invalid_signature));
    }
    std::cout << "sig_agg: aggregated=" << aggregated_count << " refused=" << refused << '\n';
    BOOST_TEST_EQ(aggregated_count, 4);
    BOOST_TEST_EQ(refused, 1);
}

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

secp::keypair keypair_of(std::span<std::uint8_t const, 32> secret_bytes) {
    auto made = secp::keypair::from_secret(secret_bytes);
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return std::move(*made);
}

secp::public_key public_of(secp::keypair const& key) {
    auto const public_key = key.public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        std::exit(boost::report_errors());
    }
    return *public_key;
}

// Round one: each signer's nonce, in sorted order, the public halves summed. False when a
// nonce is refused.
bool first_round(std::vector<secp::keypair> const& signers, std::vector<std::size_t> const& order,
                 musig::aggregate_key const& key, scalar const& message,
                 std::vector<musig::secret_nonce>& secrets,
                 std::vector<musig::public_nonce>& publics) {
    for (auto const i : order) {
        auto made = musig::generate_nonce(signers[i], key, message);
        if (!BOOST_TEST(made.has_value())) {
            return false;
        }
        secrets.push_back(std::move(made->secret_part));
        publics.push_back(made->public_part);
    }
    return true;
}

// One signer's partial signature, verified by any of them; the same one changed in one bit does
// not verify.
std::optional<musig::partial_signature> second_round_part(secp::keypair const& signer,
                                                          musig::secret_nonce secret,
                                                          musig::public_nonce const& nonce,
                                                          secp::public_key const& signer_key,
                                                          musig::aggregate_key const& key,
                                                          musig::session const& signing_session) {
    auto part = musig::partial_sign(signer, std::move(secret), key, signing_session);
    if (!BOOST_TEST(part.has_value())) {
        return std::nullopt;
    }
    BOOST_TEST(musig::partial_signature_verify(*part, nonce, signer_key, key, signing_session)
                   .has_value());
    auto changed = musig::serialize_partial_signature(*part);
    changed[31] ^= 0x01U;
    auto const reparsed = musig::parse_partial_signature(changed);
    if (BOOST_TEST(reparsed.has_value())) {
        BOOST_TEST(
            musig::partial_signature_verify(*reparsed, nonce, signer_key, key, signing_session)
                .error() == crypto::error::invalid_signature);
    }
    return *part;
}

// The aggregate checked as BIP 340's, and refused for another message.
void aggregate_verifies(std::span<musig::partial_signature const> parts,
                        musig::aggregate_key const& key, musig::session const& signing_session,
                        scalar const& message) {
    auto signature_space = lent(parts.size());
    auto const signature =
        musig::partial_signature_aggregate(signing_session, parts, signature_space);
    BOOST_TEST(all_zero(signature_space));
    if (BOOST_TEST(signature.has_value())) {
        BOOST_TEST(crypto::verify(crypto::schnorr, *signature, message, key.xonly_public_key())
                       .has_value());
        auto other_message = message;
        other_message[0] ^= 0x01U;
        BOOST_TEST(
            crypto::verify(crypto::schnorr, *signature, other_message, key.xonly_public_key())
                .error() == crypto::error::invalid_signature);
    }
}

// The signers' order is BIP 327's KeySort; each signer finds its own key's place again.
std::vector<std::size_t> sort_order(std::vector<secp::public_key> const& keys) {
    std::vector<std::size_t> order(keys.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    std::ranges::sort(order, [&](std::size_t a, std::size_t b) { return keys[a] < keys[b]; });
    return order;
}

// One signature of `signer_count` seeded signers, its keys sorted, plain or with an x-only
// tweak: two rounds, every partial signature verified, the aggregate checked as BIP 340's.
void round_trip(std::mt19937_64& generator, std::size_t signer_count, bool with_tweak) {
    std::vector<secp::keypair> signers;
    std::vector<secp::public_key> keys;
    signers.reserve(signer_count);
    keys.reserve(signer_count);
    for (std::size_t i = 0; i < signer_count; ++i) {
        signers.push_back(keypair_of(draw(generator)));
        keys.push_back(public_of(signers.back()));
    }
    auto const order = sort_order(keys);
    std::vector<secp::public_key> sorted;
    sorted.reserve(signer_count);
    for (auto const i : order) {
        sorted.push_back(keys[i]);
    }
    auto key = aggregated(sorted);
    if (with_tweak) {
        BOOST_TEST(key.tweak_xonly_add(draw(generator)).has_value());
    }
    auto const message = draw(generator);

    std::vector<musig::secret_nonce> secrets;
    std::vector<musig::public_nonce> publics;
    if (!first_round(signers, order, key, message, secrets, publics)) {
        return;
    }
    auto nonce_space = lent(signer_count);
    auto const sum = musig::nonce_aggregate(publics, nonce_space);
    BOOST_TEST(all_zero(nonce_space));
    if (!BOOST_TEST(sum.has_value())) {
        return;
    }
    auto const signing_session = session_of(*sum, message, key);

    // Round two: each signer's partial signature.
    std::vector<musig::partial_signature> parts;
    parts.reserve(signer_count);
    for (std::size_t k = 0; k < signer_count; ++k) {
        auto part = second_round_part(signers[order[k]], std::move(secrets[k]), publics[k],
                                      sorted[k], key, signing_session);
        if (!part) {
            return;
        }
        parts.push_back(*part);
    }
    aggregate_verifies(parts, key, signing_session, message);
}

void round_trips() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x3a5195ULL);
    for (int round = 0; round < 16; ++round) {
        round_trip(generator, 2, false);
        round_trip(generator, 3, false);
        round_trip(generator, 2, true);
        round_trip(generator, 3, true);
    }
}

void nonce_rules() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x90ceULL);
    auto const alice = keypair_of(draw(generator));
    auto const bob = keypair_of(draw(generator));
    std::array<secp::public_key, 2> const keys{public_of(alice), public_of(bob)};
    auto const key = aggregated(keys);
    auto const message = draw(generator);

    auto alice_nonce = musig::generate_nonce(alice, key, message, message);
    auto bob_nonce = musig::generate_nonce(bob, key);
    if (!BOOST_TEST(alice_nonce && bob_nonce)) {
        return;
    }
    std::array<musig::public_nonce, 2> const publics{
        alice_nonce->public_part,
        bob_nonce->public_part,
    };
    auto space = lent(2);
    auto const sum = musig::nonce_aggregate(publics, space);
    if (!BOOST_TEST(sum.has_value())) {
        return;
    }
    auto const signing_session = session_of(*sum, message, key);

    // A nonce made by one key pair, given to another: refused before libsecp256k1 sees it.
    BOOST_TEST(musig::partial_sign(bob, std::move(alice_nonce->secret_part), key, signing_session)
                   .error() == crypto::error::invalid_state);

    // A nonce signs once: the second use of the same object, moved again, is refused, and the
    // program does not abort (libsecp256k1's own check of a used nonce is an ARG_CHECK).
    auto nonce = std::move(bob_nonce->secret_part);
    BOOST_TEST(musig::partial_sign(bob, std::move(nonce), key, signing_session).has_value());
    // NOLINTNEXTLINE(bugprone-use-after-move): the second use of a consumed nonce is what is tested
    BOOST_TEST(musig::partial_sign(bob, std::move(nonce), key, signing_session).error() ==
               crypto::error::invalid_state);

    // A moved-from key pair: refused by generate_nonce and by partial_sign.
    auto source = keypair_of(draw(generator));
    auto fresh = musig::generate_nonce(source, key);
    auto const target = std::move(source);
    BOOST_TEST(target.public_key().has_value());
    // NOLINTBEGIN(bugprone-use-after-move): the moved-from pair is what is tested
    BOOST_TEST(musig::generate_nonce(source, key).error() == crypto::error::invalid_state);
    if (BOOST_TEST(fresh.has_value())) {
        BOOST_TEST(musig::partial_sign(source, std::move(fresh->secret_part), key, signing_session)
                       .error() == crypto::error::invalid_state);
    }
    test::expect_empty_keypair(source);
    // NOLINTEND(bugprone-use-after-move)

    // A message hash or extra input of 31 bytes.
    std::array<std::uint8_t, 31> const short_input{};
    BOOST_TEST(musig::generate_nonce(alice, key, short_input).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(musig::generate_nonce(alice, key, message, short_input).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(musig::generate_nonce(alice, key, {}, message).has_value());
}

// A workspace one byte short, and none: refused, the workspace zero afterwards.
void short_workspaces_refused(std::vector<std::byte>& space, std::span<secp::public_key const> keys,
                              std::span<musig::public_nonce const> publics,
                              musig::session const& signing_session) {
    auto const short_space = [&] {
        std::ranges::fill(space, std::byte{0xa5});
        return std::span(space).first(space.size() - 1);
    };
    BOOST_TEST(musig::key_aggregate(keys, short_space()).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(std::span(space).first(space.size() - 1)));
    BOOST_TEST(musig::nonce_aggregate(publics, short_space()).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(std::span(space).first(space.size() - 1)));
    auto const part = musig::parse_partial_signature(scalar{});
    if (BOOST_TEST(part.has_value())) {
        std::array<musig::partial_signature, 2> const parts{*part, *part};
        BOOST_TEST(
            musig::partial_signature_aggregate(signing_session, parts, short_space()).error() ==
            crypto::error::invalid_input_size);
        BOOST_TEST(all_zero(std::span(space).first(space.size() - 1)));
        BOOST_TEST(musig::partial_signature_aggregate(signing_session, parts, {}).error() ==
                   crypto::error::invalid_input_size);
    }
    BOOST_TEST(musig::key_aggregate(keys, {}).error() == crypto::error::invalid_input_size);
    BOOST_TEST(musig::nonce_aggregate(publics, {}).error() == crypto::error::invalid_input_size);
}

// Encodings of the wrong size, and a public nonce of the point at infinity.
void wrong_size_encodings_refused() {
    std::array<std::uint8_t, 65> const nonce_65{};
    std::array<std::uint8_t, 31> const signature_31{};
    BOOST_TEST(musig::parse_public_nonce(nonce_65).error() == crypto::error::invalid_input_size);
    BOOST_TEST(musig::parse_aggregate_nonce(nonce_65).error() == crypto::error::invalid_input_size);
    BOOST_TEST(musig::parse_partial_signature(signature_31).error() ==
               crypto::error::invalid_input_size);
    // A public nonce of the point at infinity, which only an aggregate nonce may hold.
    std::array<std::uint8_t, musig::public_nonce_size> const zero_nonce{};
    BOOST_TEST(musig::parse_public_nonce(zero_nonce).error() == crypto::error::invalid_point);
    BOOST_TEST(musig::parse_aggregate_nonce(zero_nonce).has_value());
}

void refusals() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x7e7ULL);
    auto const alice = keypair_of(draw(generator));
    std::array<secp::public_key, 2> const keys{
        public_of(alice),
        public_of(keypair_of(draw(generator))),
    };
    auto const key = aggregated(keys);
    auto const nonce = musig::generate_nonce(alice, key);
    if (!BOOST_TEST(nonce.has_value())) {
        return;
    }
    std::array<musig::public_nonce, 2> const publics{
        nonce->public_part,
        nonce->public_part,
    };

    // No keys, nonces or partial signatures: invalid_input_size, the workspace zero afterwards.
    auto space = lent(2);
    BOOST_TEST(musig::key_aggregate({}, space).error() == crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(space));
    std::ranges::fill(space, std::byte{0xa5});
    BOOST_TEST(musig::nonce_aggregate({}, space).error() == crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(space));
    auto const sum = musig::nonce_aggregate(publics, space);
    if (!BOOST_TEST(sum.has_value())) {
        return;
    }
    auto const signing_session = session_of(*sum, draw(generator), key);
    std::ranges::fill(space, std::byte{0xa5});
    BOOST_TEST(musig::partial_signature_aggregate(signing_session, {}, space).error() ==
               crypto::error::invalid_input_size);
    BOOST_TEST(all_zero(space));
    short_workspaces_refused(space, keys, publics, signing_session);
    wrong_size_encodings_refused();
}

// The aggregate key's full point and x-only form agree, a plain tweak acts on the full point,
// and the tweaks match tweak.hpp's on the same point.
void aggregate_key_forms() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xa66ULL);
    std::array<secp::public_key, 2> const keys{
        public_of(keypair_of(draw(generator))),
        public_of(keypair_of(draw(generator))),
    };
    auto key = aggregated(keys);
    auto const full = key.full_public_key().compressed();
    BOOST_TEST(std::ranges::equal(std::span(full).subspan(1), key.xonly_public_key()));
    scalar tweak_bytes{};
    tweak_bytes[31] = 7;
    auto const before = key.full_public_key();
    BOOST_TEST(key.tweak_add(tweak_bytes).has_value());
    secp256k1_pubkey expected{};
    auto const encoded = before.compressed();
    BOOST_TEST(secp256k1_ec_pubkey_parse(secp256k1_context_static, &expected, encoded.data(),
                                         encoded.size()) == 1);
    BOOST_TEST(secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &expected,
                                             tweak_bytes.data()) == 1);
    std::array<std::uint8_t, 33> expected_bytes{};
    std::size_t written = expected_bytes.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_COMPRESSED;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, expected_bytes.data(), &written,
                                  &expected, flags);
    BOOST_TEST(key.full_public_key().compressed() == expected_bytes);
}

}  // namespace

int main() {
    key_sort();
    key_agg();
    nonce_agg();
    sign_verify();
    tweak();
    sig_agg();
    round_trips();
    nonce_rules();
    refusals();
    aggregate_key_forms();
    return webcpp::test::exit_status(boost::report_errors());
}
