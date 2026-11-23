// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's x-only tweak against BIP341's wallet-test-vectors.json, as a domain library
// would use it: the test computes BIP341's tweak, tagged_hash("TapTweak", internal_key ||
// merkle_root), with libsecp256k1's tagged hash, and passes it. Every scriptPubKey case's
// output key through tweak_xonly, and every key-path spending input's key pair tweaked in
// place through keypair::tweak_xonly, compared through its public key with the vector's
// tweaked secret key and through its BIP340 signature (all-zero aux) of the sighash with the
// expected witness; then the tweak's refusals.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_checks.hpp"
#include "support/secp256k1_data.hpp"

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
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using bytes = std::vector<std::uint8_t>;

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

// A hex field, or no bytes for a JSON null (a key-path-only output's merkle root).
bytes hex_or_empty(json::value const& v) {
    return v.is_null() ? bytes() : test::from_hex(str(v));
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(json::value const& v) {
    auto const b = test::from_hex(str(v));
    BOOST_TEST_EQ(b.size(), N);
    std::array<std::uint8_t, N> out{};
    std::ranges::copy(std::span(b).first((std::min)(N, b.size())), out.begin());
    return out;
}

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

// BIP341's tweak of an internal key and a merkle root (empty, or 32 bytes).
std::array<std::uint8_t, 32> tap_tweak(std::span<std::uint8_t const, 32> internal_key,
                                       std::span<std::uint8_t const> merkle_root) {
    static constexpr std::array<unsigned char, 8> tag{'T', 'a', 'p', 'T', 'w', 'e', 'a', 'k'};
    bytes message(internal_key.begin(), internal_key.end());
    message.insert(message.end(), merkle_root.begin(), merkle_root.end());
    std::array<std::uint8_t, 32> tweak{};
    secp256k1_tagged_sha256(secp256k1_context_static, tweak.data(), tag.data(), tag.size(),
                            message.data(), message.size());
    return tweak;
}

int script_pub_keys(json::value const& doc) {
    int cases = 0;
    for (auto const& c : doc.at("scriptPubKey").as_array()) {
        ++cases;
        auto const internal = fixed<32>(c.at("given").at("internalPubkey"));
        auto const root = hex_or_empty(c.at("intermediary").at("merkleRoot"));
        auto const expected = test::from_hex(str(c.at("intermediary").at("tweakedPubkey")));
        auto const output = secp::tweak_xonly(internal, tap_tweak(internal, root));
        BOOST_TEST(output.has_value());
        if (output && !std::ranges::equal(output->key, expected)) {
            fail("scriptPubKey " + std::to_string(cases) + ": output key differs");
        }
        // The scriptPubKey is OP_1, a 32-byte push, and the output key.
        auto const script = test::from_hex(str(c.at("expected").at("scriptPubKey")));
        BOOST_TEST(output && script.size() == 34 &&
                   std::ranges::equal(std::span(script).subspan(2), output->key));
    }
    return cases;
}

// One key-path spending input: its internal key pair tweaked, compared with the vector's
// tweaked secret key, output key and witness.
void check_input(json::value const& input, int index) {
    auto const& given = input.at("given");
    auto const& intermediary = input.at("intermediary");
    auto key = *secp::keypair::from_secret(fixed<32>(given.at("internalPrivkey")));
    auto const internal = fixed<32>(intermediary.at("internalPubkey"));
    BOOST_TEST(key.public_key()->xonly() == internal);
    auto const tweak = tap_tweak(internal, hex_or_empty(given.at("merkleRoot")));
    BOOST_TEST(key.tweak_xonly(tweak).has_value());

    // The tweaked pair is the vector's tweaked secret key: the same SEC1 public key, its parity
    // included.
    auto const reference =
        *secp::keypair::from_secret(fixed<32>(intermediary.at("tweakedPrivkey")));
    BOOST_TEST(*key.public_key() == *reference.public_key());
    auto const output = secp::tweak_xonly(internal, tweak);
    BOOST_TEST(output.has_value());
    if (!output) {
        return;
    }
    BOOST_TEST(key.public_key()->xonly() == output->key);
    BOOST_TEST_EQ(output->parity, key.public_key()->compressed()[0] == 0x03 ? 1 : 0);

    // Its BIP340 signature of the sighash, with an all-zero aux, is the witness's first 64
    // bytes (a 65th is the hash type, when it is not SIGHASH_DEFAULT).
    std::array<std::uint8_t, 32> const aux{};
    auto const sighash = fixed<32>(intermediary.at("sigHash"));
    auto const signature = key.sign(crypto::schnorr, sighash, aux);
    auto const& expected = input.at("expected");
    auto const& witnesses = expected.at("witness").as_array();
    auto const witness = test::from_hex(str(witnesses.at(0)));
    BOOST_TEST(witness.size() == 64 || witness.size() == 65);
    // A 65th byte is the hash type, which SIGHASH_DEFAULT (0) leaves out.
    auto const hash_type = given.at("hashType").to_number<int>();
    if (witness.size() == 65) {
        BOOST_TEST_EQ(int{witness.back()}, hash_type);
    } else {
        BOOST_TEST_EQ(hash_type, 0);
    }
    if (!signature || witness.size() < 64 ||
        !std::ranges::equal(signature->bytes(), std::span(witness).first(64))) {
        fail("keyPathSpending input " + std::to_string(index) + ": signature differs");
    }
    BOOST_TEST(signature && crypto::verify(crypto::schnorr, *signature, sighash, output->key));
}

int key_path_inputs(json::value const& doc) {
    int inputs = 0;
    for (auto const& spending : doc.at("keyPathSpending").as_array()) {
        for (auto const& input : spending.at("inputSpending").as_array()) {
            check_input(input, ++inputs);
        }
    }
    return inputs;
}

void refusals() {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x11);
    auto key = *secp::keypair::from_secret(secret);
    auto const internal = key.public_key()->xonly();
    std::array<std::uint8_t, 32> const zero{};
    // A tweak of zero leaves the key as it is.
    auto const same = secp::tweak_xonly(internal, zero);
    BOOST_TEST(same.has_value() && same->key == internal);
    // A tweak not below the group order is refused, by both forms.
    std::array<std::uint8_t, 32> over{};
    over.fill(0xff);
    BOOST_TEST(secp::tweak_xonly(internal, over).error() == crypto::error::invalid_secret_key);
    std::array<std::uint8_t, 32> const not_a_point{};  // x = 0 has no point
    BOOST_TEST(secp::tweak_xonly(not_a_point, zero).error() == crypto::error::invalid_public_key);
    {
        auto refused = *secp::keypair::from_secret(secret);
        BOOST_TEST(refused.tweak_xonly(over).error() == crypto::error::invalid_secret_key);
        // Refused, the pair is wiped and empty, as moved from: every operation says so.
        test::expect_empty_keypair(refused);
    }

    // NOLINTBEGIN(bugprone-use-after-move): a moved-from pair is what this case tests
    auto moved = std::move(key);
    BOOST_TEST(key.tweak_xonly(zero).error() == crypto::error::invalid_state);
    // NOLINTEND(bugprone-use-after-move)
    // The tweaked pair moves as any pair does.
    std::array<std::uint8_t, 32> tweak{};
    tweak.fill(0x22);
    BOOST_TEST(moved.tweak_xonly(tweak).has_value());
    auto const output = *secp::tweak_xonly(internal, tweak);
    auto const again = std::move(moved);
    BOOST_TEST(again.public_key()->xonly() == output.key);
}

}  // namespace

int main() {
    auto const text = test::read_file(WEBCPP_TEST_BIPS "/bip-0341/wallet-test-vectors.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    BOOST_TEST(!ec);
    if (!ec) {
        auto const outputs = script_pub_keys(doc);
        auto const inputs = key_path_inputs(doc);
        std::cout << "bip341: scriptPubKey=" << outputs << " keyPathSpending inputs=" << inputs
                  << '\n';
        BOOST_TEST_EQ(outputs, 7);
        BOOST_TEST_EQ(inputs, 7);
    }
    refusals();
    return webcpp::test::exit_status(boost::report_errors());
}
