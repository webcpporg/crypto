// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1 against Wycheproof (spec 8.1): the Bitcoin ECDSA vectors through verify_ecdsa,
// and the ECDH vectors, in ASN.1 and JWK form, through libsecp256k1's C API and webcpp's
// keypair::ecdh, which must agree with it.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/sha2.hpp>
#include <boost/json.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
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

void fail(std::string const& message) {
    BOOST_ERROR(message.c_str());
}

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

void ecdsa_bitcoin() {
    auto const doc = load("ecdsa_secp256k1_sha256_bitcoin_test");
    int total = 0;
    int valid = 0;
    int skipped = 0;
    int invalid = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const key = test::from_hex(str(group.at("publicKey").at("uncompressed")));
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const message = test::from_hex(str(t.at("msg")));
            boost::hash2::sha2_256 hasher;
            hasher.update(message.data(), message.size());
            auto const digest = hasher.result();
            std::array<std::uint8_t, 32> hash{};
            std::ranges::copy(digest, hash.begin());

            auto const der = test::from_hex(str(t.at("sig")));
            secp256k1_ecdsa_signature parsed{};
            std::array<std::uint8_t, 64> compact{};
            // An empty DER has no data pointer to give the parser, which refuses one.
            if (der.empty() ||
                secp256k1_ecdsa_signature_parse_der(secp256k1_context_static, &parsed, der.data(),
                                                    der.size()) == 0) {
                ++skipped;
                continue;
            }
            BOOST_TEST_EQ(secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static,
                                                                      compact.data(), &parsed),
                          1);
            auto const result = secp::verify_ecdsa(compact, hash, key);
            auto const verdict = str(t.at("result"));
            if (verdict == "valid") {
                ++valid;
                if (!result.has_value()) {
                    fail("tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>()) +
                         ": valid signature refused");
                }
            } else if (verdict == "invalid") {
                ++invalid;
                BOOST_TEST(result.has_error() &&
                           result.error() == crypto::error::invalid_signature);
            } else {
                fail("unexpected result: " + verdict);
            }
        }
    }
    std::cout << "ecdsa bitcoin: tests=" << total << " valid_verified=" << valid
              << " skipped=" << skipped << " invalid_refused=" << invalid << '\n';
    BOOST_TEST_EQ(total, 464);
    BOOST_TEST_EQ(valid, 162);
    BOOST_TEST_EQ(skipped, 190);
    BOOST_TEST_EQ(invalid, 112);
}

// The ECDH hash function of the test: the x coordinate, as Wycheproof's shared secret.
int copy_x(unsigned char* output, unsigned char const* x32, unsigned char const* /*y32*/,
           void* /*data*/) {
    std::memcpy(output, x32, 32);
    return 1;
}

struct counts {
    int taken = 0;
    int skipped = 0;
    int valid = 0;
    int invalid = 0;
    int acceptable = 0;
    int acceptable_taken = 0;
    int acceptable_refused = 0;
    int compressed = 0;
    int uncompressed = 0;
    int refused = 0;
    int bad_scalar = 0;
    int agreed_default = 0;
};

// What libsecp256k1's C API makes of a taken case: the point parsed, and the shared x.
struct c_api_result {
    secp256k1_pubkey parsed{};
    bool parses = false;
    bool computes = false;
};

// The C API on one taken case, against its verdict: a valid case agrees with the expected x,
// an invalid one is refused, an acceptable one is counted by what the C API does.
c_api_result c_api_case(std::string const& label, std::string const& verdict, bytes const& point,
                        std::array<std::uint8_t, 32> const& scalar, bytes const& shared,
                        counts& c) {
    c_api_result r;
    r.parses = secp256k1_ec_pubkey_parse(secp256k1_context_static, &r.parsed, point.data(),
                                         point.size()) == 1;
    std::array<std::uint8_t, 32> x{};
    r.computes = r.parses && secp256k1_ecdh(secp256k1_context_static, x.data(), &r.parsed,
                                            scalar.data(), copy_x, nullptr) == 1;
    if (!r.computes) {
        ++c.refused;
    }
    if (verdict == "valid") {
        ++c.valid;
        BOOST_TEST(r.computes);
        if (r.computes && !std::ranges::equal(x, shared)) {
            fail(label + ": shared secret differs");
        }
    } else if (verdict == "invalid") {
        ++c.invalid;
        if (r.computes) {
            fail(label + ": invalid case taken by the C API");
        }
    } else {
        ++c.acceptable;
        ++(r.computes ? c.acceptable_taken : c.acceptable_refused);
    }
    return r;
}

// One taken case: the point as SEC1 bytes and the private key as 32 bytes, through the C API,
// then through keypair::ecdh, which refuses what the C API cannot parse and otherwise equals
// the C API's default hash.
void ecdh_case(std::string const& label, std::string const& verdict, bytes const& point,
               std::array<std::uint8_t, 32> const& scalar, bytes const& shared, counts& c) {
    ++c.taken;
    auto const r = c_api_case(label, verdict, point, scalar, shared, c);
    auto const key = secp::keypair::make(scalar);
    if (!key.has_value()) {
        // A scalar libsecp256k1 refuses (zero or not below the order) gives no shared secret.
        ++c.bad_scalar;
        BOOST_TEST(!r.computes);
        return;
    }
    auto const mine = key->ecdh(point);
    if (!r.parses) {
        BOOST_TEST(mine.has_error() && mine.error() == crypto::error::invalid_public_key);
        return;
    }
    std::array<std::uint8_t, 32> reference{};
    bool const reference_ok = secp256k1_ecdh(secp256k1_context_static, reference.data(), &r.parsed,
                                             scalar.data(), nullptr, nullptr) == 1;
    BOOST_TEST_EQ(reference_ok, r.computes);
    if (!reference_ok) {
        return;
    }
    if (mine.has_value() && *mine == reference) {
        ++c.agreed_default;
    } else {
        fail(label + ": ecdh differs from the C API's default");
    }
}

void print(char const* name, counts const& c) {
    std::cout << name << ": taken=" << c.taken << " skipped=" << c.skipped
              << " uncompressed=" << c.uncompressed << " compressed=" << c.compressed
              << " valid=" << c.valid << " invalid=" << c.invalid << " acceptable=" << c.acceptable
              << " acceptable_taken=" << c.acceptable_taken
              << " acceptable_refused=" << c.acceptable_refused << " refused_by_c_api=" << c.refused
              << " bad_scalar=" << c.bad_scalar << " agreed_with_default_hash=" << c.agreed_default
              << '\n';
}

void ecdh_asn() {
    constexpr std::string_view uncompressed_prefix =
        "3056301006072a8648ce3d020106052b8104000a034200";
    constexpr std::string_view compressed_prefix = "3036301006072a8648ce3d020106052b8104000a032200";
    auto const doc = load("ecdh_secp256k1_test");
    counts c;
    int total = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const label =
                "ecdh asn tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>());
            auto const pub = str(t.at("public"));
            std::string_view tail;
            if (pub.size() == 2 * ((uncompressed_prefix.size() / 2) + 65) &&
                std::string_view(pub).starts_with(uncompressed_prefix)) {
                tail = std::string_view(pub).substr(uncompressed_prefix.size());
                ++c.uncompressed;
            } else if (pub.size() == 2 * ((compressed_prefix.size() / 2) + 33) &&
                       std::string_view(pub).starts_with(compressed_prefix)) {
                tail = std::string_view(pub).substr(compressed_prefix.size());
                ++c.compressed;
            } else {
                ++c.skipped;
                continue;
            }
            auto const priv = test::from_hex(str(t.at("private")));
            ecdh_case(label, str(t.at("result")), test::from_hex(tail), test::scalar32(priv),
                      test::from_hex(str(t.at("shared"))), c);
        }
    }
    print("ecdh asn", c);
    BOOST_TEST_EQ(total, 752);
    BOOST_TEST_EQ(c.taken, 496);
    BOOST_TEST_EQ(c.uncompressed, 492);
    BOOST_TEST_EQ(c.compressed, 4);
    BOOST_TEST_EQ(c.skipped, 256);
    BOOST_TEST_EQ(c.valid, 473);
    BOOST_TEST_EQ(c.invalid, 21);
    BOOST_TEST_EQ(c.acceptable, 2);
    BOOST_TEST_EQ(c.acceptable_taken, 1);
    BOOST_TEST_EQ(c.acceptable_refused, 1);
    BOOST_TEST_EQ(c.agreed_default, c.valid + c.acceptable_taken);
}

void ecdh_jwk() {
    auto const doc = load("ecdh_secp256k1_webcrypto_test");
    counts c;
    int total = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            ++total;
            auto const label =
                "ecdh jwk tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>());
            auto const& pub = t.at("public").as_object();
            if (str(pub.at("crv")) != "P-256K") {
                ++c.skipped;
                continue;
            }
            bytes point{0x04};
            for (char const* coordinate : {"x", "y"}) {
                auto const part = test::from_base64url(str(pub.at(coordinate)));
                point.insert(point.end(), part.begin(), part.end());
            }
            auto const d = test::from_base64url(str(t.at("private").at("d")));
            ecdh_case(label, str(t.at("result")), point, test::scalar32(d),
                      test::from_hex(str(t.at("shared"))), c);
        }
    }
    print("ecdh jwk", c);
    BOOST_TEST_EQ(total, 496);
    BOOST_TEST_EQ(c.taken, 491);
    BOOST_TEST_EQ(c.valid, 473);
    BOOST_TEST_EQ(c.invalid, 18);
    BOOST_TEST_EQ(c.skipped, 5);
    BOOST_TEST_EQ(c.agreed_default, c.valid);
}

}  // namespace

int main() {
    ecdsa_bitcoin();
    ecdh_asn();
    ecdh_jwk();
    return webcpp::test::exit_status(boost::report_errors());
}
