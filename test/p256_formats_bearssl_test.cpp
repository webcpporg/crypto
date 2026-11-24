// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256's keys in files, on BearSSL: RFC 5480's SPKI and PKCS#8 with RFC 5915's ECPrivateKey, by
// fixed layouts, strict, and PEM around both (pem::armour and pem::unarmour, on libsodium). The
// header's constants equal the DER a small builder writes here from the ASN.1; RFC 6979's key and
// 50 generated key pairs round-trip; BearSSL's own encoder, br_encode_ec_pkcs8_der, writes the
// same PKCS#8 bytes, an oracle of the layout; every malformed input is invalid_encoding, and an
// encoder that refuses writes nothing; Wycheproof's 612 SPKIs of its P-256 ECDH vectors are
// decoded, then derived (WEBCPP_TEST_WYCHEPROOF), each refusal of a valid or acceptable case
// listed with its reason.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/p256_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <bearssl.h>

#ifdef WEBCPP_TEST_WYCHEPROOF
#include "support/test_data.hpp"

#include <boost/json.hpp>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
namespace pem = webcpp::crypto::pem;
namespace p256 = webcpp::crypto::curves::p256;
namespace data = webcpp::test::p256;
namespace test = webcpp::test;

using crypto::error;
using p256::keypair;
using p256::public_key;
using bytes = std::vector<std::uint8_t>;

static_assert(p256::max_spki_size == 91);
static_assert(p256::max_pkcs8_size == 138);
static_assert(crypto::detail::p256_spki_prefix.size() == 26);
static_assert(crypto::detail::p256_pkcs8_prefix.size() == 36);
static_assert(crypto::detail::p256_pkcs8_infix.size() == 5);
static_assert(std::is_same_v<decltype(p256::decode_spki(std::declval<bytes const&>())),
                             boost::system::result<public_key>>);
static_assert(std::is_same_v<decltype(p256::decode_pkcs8(std::declval<bytes const&>())),
                             boost::system::result<keypair>>);

// The ASN.1 of the formats, written by hand here so that the header's constants are checked
// against something they were not copied from.
bytes cat(std::initializer_list<bytes> parts) {
    bytes out;
    for (auto const& part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

// A DER element: the tag, the length in its shortest form, the content.
bytes der(std::uint8_t tag, bytes const& content) {
    bytes out{tag};
    if (content.size() < 0x80) {
        out.push_back(static_cast<std::uint8_t>(content.size()));
    } else {
        out.push_back(0x81);
        out.push_back(static_cast<std::uint8_t>(content.size()));
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// The OIDs' contents: id-ecPublicKey (1.2.840.10045.2.1), secp256r1 (1.2.840.10045.3.1.7) and
// secp256k1 (1.3.132.0.10).
bytes ec_public_key_oid() {
    return test::from_hex("2a8648ce3d0201");
}

bytes p256_oid() {
    return test::from_hex("2a8648ce3d030107");
}

bytes secp256k1_oid() {
    return test::from_hex("2b8104000a");
}

bytes algorithm(bytes const& curve) {
    return der(0x30, cat({der(0x06, ec_public_key_oid()), der(0x06, curve)}));
}

bytes bit_string(bytes const& point) {
    return der(0x03, cat({{0x00}, point}));
}

bytes spki_of(bytes const& curve, bytes const& point) {
    return der(0x30, cat({algorithm(curve), bit_string(point)}));
}

// RFC 5915's ECPrivateKey, with its optional fields.
struct ec_private_key {
    std::uint8_t version = 1;
    bytes scalar;
    bool parameters = false;
    bytes point;  // none when empty
};

bytes encoded(ec_private_key const& key) {
    bytes content = cat({der(0x02, {key.version}), der(0x04, key.scalar)});
    if (key.parameters) {
        content = cat({content, der(0xa0, der(0x06, p256_oid()))});
    }
    if (!key.point.empty()) {
        content = cat({content, der(0xa1, bit_string(key.point))});
    }
    return der(0x30, content);
}

bytes pkcs8_of(std::uint8_t version, bytes const& curve, ec_private_key const& key) {
    return der(0x30, cat({der(0x02, {version}), algorithm(curve), der(0x04, encoded(key))}));
}

// What a key pair holds, as bytes: its scalar and its uncompressed point.
bytes scalar_of(keypair const& pair) {
    auto const scalar = pair.secret();
    if (!BOOST_TEST(scalar.has_value())) {
        return bytes(32);
    }
    return {scalar->bytes().begin(), scalar->bytes().end()};
}

bytes point_of(keypair const& pair) {
    auto const key = pair.public_key();
    if (!BOOST_TEST(key.has_value())) {
        return bytes(65);
    }
    auto const point = key->uncompressed();
    return {point.begin(), point.end()};
}

// SEC 1's compressed form of an uncompressed point: 02 or 03 by y's parity, then x.
bytes compressed(bytes const& point) {
    bytes out{static_cast<std::uint8_t>(0x02U | (point[64] & 1U))};
    out.insert(out.end(), point.begin() + 1, point.begin() + 33);
    return out;
}

bytes spki(public_key const& key) {
    std::array<std::uint8_t, p256::max_spki_size> out{};
    auto const size = p256::encode_spki(key, out);
    if (!BOOST_TEST(size.has_value())) {
        return {};
    }
    return {out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*size)};
}

bytes pkcs8(keypair const& pair) {
    std::array<std::uint8_t, p256::max_pkcs8_size> out{};
    auto const size = p256::encode_pkcs8(pair, out);
    if (!BOOST_TEST(size.has_value())) {
        return {};
    }
    return {out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*size)};
}

keypair rfc6979_pair() {
    auto made = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return std::move(*made);
}

// The constants are the DER the builder writes, and RFC 6979's key gives its own point.
void constants() {
    auto const pair = rfc6979_pair();
    auto const point = point_of(pair);
    BOOST_TEST(std::ranges::equal(point, data::rfc6979_public));
    auto const key = pair.public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    BOOST_TEST_EQ(test::to_hex(spki(*key)), test::to_hex(spki_of(p256_oid(), point)));
    BOOST_TEST_EQ(
        test::to_hex(pkcs8(pair)),
        test::to_hex(pkcs8_of(
            0, p256_oid(),
            {.version = 1, .scalar = scalar_of(pair), .parameters = false, .point = point})));
}

// One key pair: its SPKI, 91 bytes, decodes to its point and encodes again to the same bytes; its
// PKCS#8, 138 bytes, decodes to a key pair of the same scalar and point.
void round_trip(keypair const& pair) {
    auto const key = pair.public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const public_encoding = spki(*key);
    BOOST_TEST_EQ(public_encoding.size(), 91U);
    auto const decoded_key = p256::decode_spki(public_encoding);
    if (BOOST_TEST(decoded_key.has_value())) {
        BOOST_TEST(decoded_key->uncompressed() == key->uncompressed());
        BOOST_TEST(spki(*decoded_key) == public_encoding);
    }
    auto const private_encoding = pkcs8(pair);
    BOOST_TEST_EQ(private_encoding.size(), 138U);
    auto const decoded_pair = p256::decode_pkcs8(private_encoding);
    if (BOOST_TEST(decoded_pair.has_value())) {
        BOOST_TEST(scalar_of(*decoded_pair) == scalar_of(pair));
        BOOST_TEST(point_of(*decoded_pair) == point_of(pair));
        BOOST_TEST(pkcs8(*decoded_pair) == private_encoding);
    }
}

// RFC 6979's key, then 50 key pairs from the system's generator.
void round_trips() {
    round_trip(rfc6979_pair());
    for (int round = 0; round < 50; ++round) {
        auto const generated = keypair::generate();
        if (BOOST_TEST(generated.has_value())) {
            round_trip(*generated);
        }
    }
}

// BearSSL's PKCS#8 of a key pair, with its public key or with none (a null br_ec_public_key).
bytes bearssl_pkcs8(keypair const& pair, bool with_public_key) {
    auto scalar = pair.secret();
    if (!BOOST_TEST(scalar.has_value())) {
        return {};
    }
    auto point = point_of(pair);
    br_ec_private_key const private_key{
        .curve = BR_EC_secp256r1,
        .x = scalar->writable().data(),
        .xlen = scalar->writable().size(),
    };
    br_ec_public_key const public_point{
        .curve = BR_EC_secp256r1,
        .q = point.data(),
        .qlen = point.size(),
    };
    br_ec_public_key const* const public_part = with_public_key ? &public_point : nullptr;
    std::size_t const size = br_encode_ec_pkcs8_der(nullptr, &private_key, public_part);
    bytes out(size);
    BOOST_TEST_EQ(br_encode_ec_pkcs8_der(out.data(), &private_key, public_part), size);
    return out;
}

// BearSSL's encoder writes exactly encode_pkcs8's bytes: RFC 6979's key and 10 generated ones.
void bearssl_writes_the_same() {
    BOOST_TEST_EQ(test::to_hex(bearssl_pkcs8(rfc6979_pair(), true)),
                  test::to_hex(pkcs8(rfc6979_pair())));
    for (int round = 0; round < 10; ++round) {
        auto const generated = keypair::generate();
        if (BOOST_TEST(generated.has_value())) {
            BOOST_TEST(bearssl_pkcs8(*generated, true) == pkcs8(*generated));
        }
    }
}

void refused_spki(std::string const& label, bytes const& encoding) {
    auto const decoded = p256::decode_spki(encoding);
    if (!BOOST_TEST(decoded.has_error()) ||
        !BOOST_TEST(decoded.error() == error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
}

void refused_pkcs8(std::string const& label, bytes const& encoding) {
    auto const decoded = p256::decode_pkcs8(encoding);
    if (!BOOST_TEST(decoded.has_error()) ||
        !BOOST_TEST(decoded.error() == error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
}

// Every malformed SPKI is invalid_encoding.
void spki_refusals(bytes const& point) {
    auto const good = spki_of(p256_oid(), point);
    BOOST_TEST(p256::decode_spki(good).has_value());
    refused_spki("empty", {});
    refused_spki("secp256k1's OID", spki_of(secp256k1_oid(), point));
    // 03 22 00 and 33 bytes, the form some tools emit: BearSSL decodes no compressed point.
    auto const compressed_spki = spki_of(p256_oid(), compressed(point));
    BOOST_TEST_EQ(test::to_hex(bytes(compressed_spki.begin() + 23, compressed_spki.begin() + 26)),
                  "032200");
    refused_spki("compressed point", compressed_spki);
    auto off_curve = point;
    off_curve[64] ^= 1U;
    refused_spki("off the curve", spki_of(p256_oid(), off_curve));
    refused_spki("trailing byte", cat({good, {0x00}}));
    refused_spki("truncated by one", bytes(good.begin(), good.end() - 1));
    // 30 81 59: the outer length in long form, which DER forbids for a length below 128.
    refused_spki("long-form length",
                 cat({{0x30, 0x81, 0x59}, bytes(good.begin() + 2, good.end())}));
    auto unused_bits = good;
    unused_bits[25] = 0x01;
    refused_spki("unused bits", unused_bits);
    auto hybrid = point;
    hybrid[0] = static_cast<std::uint8_t>(0x06U | (point[64] & 1U));
    refused_spki("hybrid prefix", spki_of(p256_oid(), hybrid));
}

// Every malformed PKCS#8 is invalid_encoding.
void pkcs8_refusals(keypair const& pair) {
    auto const scalar = scalar_of(pair);
    auto const point = point_of(pair);
    auto const other = keypair::generate();
    if (!BOOST_TEST(other.has_value())) {
        return;
    }
    auto const with = [&scalar, &point](ec_private_key key) {
        if (key.scalar.empty()) {
            key.scalar = scalar;
        }
        if (key.point.empty()) {
            key.point = point;
        }
        return key;
    };
    auto const good = pkcs8_of(0, p256_oid(), with({}));
    BOOST_TEST(p256::decode_pkcs8(good).has_value());
    refused_pkcs8("empty", {});
    refused_pkcs8("secp256k1's OID", pkcs8_of(0, secp256k1_oid(), with({})));
    refused_pkcs8("trailing byte", cat({good, {0x00}}));
    refused_pkcs8("truncated by one", bytes(good.begin(), good.end() - 1));
    // BearSSL's encoder with a null public key writes ECPrivateKey without its [1] publicKey.
    auto const without_public_key = bearssl_pkcs8(pair, false);
    BOOST_TEST_EQ(without_public_key.size(), 67U);
    refused_pkcs8("no public key", without_public_key);
    // [0] parameters inside ECPrivateKey, the form `openssl ec` writes outside PKCS#8.
    refused_pkcs8("[0] parameters",
                  pkcs8_of(0, p256_oid(),
                           with({.version = 1, .scalar = {}, .parameters = true, .point = {}})));
    refused_pkcs8(
        "another key's public key",
        pkcs8_of(
            0, p256_oid(),
            with({.version = 1, .scalar = {}, .parameters = false, .point = point_of(*other)})));
    refused_pkcs8(
        "compressed public key",
        pkcs8_of(
            0, p256_oid(),
            with({.version = 1, .scalar = {}, .parameters = false, .point = compressed(point)})));
    refused_pkcs8(
        "zero scalar",
        pkcs8_of(0, p256_oid(),
                 with({.version = 1, .scalar = bytes(32), .parameters = false, .point = {}})));
    refused_pkcs8("scalar n", pkcs8_of(0, p256_oid(),
                                       with({
                                           .version = 1,
                                           .scalar = bytes(data::order.begin(), data::order.end()),
                                           .parameters = false,
                                           .point = {},
                                       })));
    // 02 01 01 in place of 02 01 00: PKCS#8 version 1.
    refused_pkcs8("version 1", pkcs8_of(1, p256_oid(), with({})));
    refused_pkcs8("ECPrivateKey version 0",
                  pkcs8_of(0, p256_oid(),
                           with({.version = 0, .scalar = {}, .parameters = false, .point = {}})));
    // The outer length, 135, takes the long form 81 87; the longer 82 00 87 is not DER.
    refused_pkcs8("long-form length",
                  cat({{0x30, 0x82, 0x00, 0x87}, bytes(good.begin() + 3, good.end())}));
}

// An encoder that refuses writes nothing: a buffer one byte short, a moved-from key pair.
// NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state is
// what is tested.
void encoder_refusals() {
    auto pair = rfc6979_pair();
    auto const key = pair.public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    std::array<std::uint8_t, p256::max_pkcs8_size> out{};
    out.fill(0xa5);
    auto const untouched = [&out] {
        return std::ranges::all_of(out, [](std::uint8_t b) { return b == 0xa5; });
    };
    auto const short_spki = p256::encode_spki(*key, std::span(out).first(p256::max_spki_size - 1));
    BOOST_TEST(short_spki.has_error() && short_spki.error() == error::invalid_input_size);
    auto const short_pkcs8 =
        p256::encode_pkcs8(pair, std::span(out).first(p256::max_pkcs8_size - 1));
    BOOST_TEST(short_pkcs8.has_error() && short_pkcs8.error() == error::invalid_input_size);
    BOOST_TEST(untouched());
    keypair const moved = std::move(pair);
    auto const empty = p256::encode_pkcs8(pair, out);
    BOOST_TEST(empty.has_error() && empty.error() == error::invalid_state);
    BOOST_TEST(untouched());
    BOOST_TEST(p256::encode_pkcs8(moved, out).has_value());
}

// NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)

void refusals() {
    auto const pair = rfc6979_pair();
    spki_refusals(point_of(pair));
    pkcs8_refusals(pair);
    encoder_refusals();
}

// DER as PEM under a label, of exactly the size armoured_size gives.
std::string armoured(std::string_view label, bytes const& encoding) {
    std::string text(pem::armoured_size(label.size(), encoding.size()), '\0');
    auto const written = pem::armour(label, encoding, text);
    if (!BOOST_TEST(written.has_value()) || !BOOST_TEST_EQ(*written, text.size())) {
        return {};
    }
    return text;
}

// The DER of PEM under a label.
bytes unarmoured(std::string_view label, std::string_view text) {
    bytes out(text.size());
    auto const read = pem::unarmour(label, text, out);
    if (!BOOST_TEST(read.has_value())) {
        return {};
    }
    out.resize(*read);
    return out;
}

// RFC 6979's key as PEM SPKI and PEM PKCS#8 on the pem family's default, libsodium: each text
// unarmours to the same DER, which decodes to the same key.
void pem_round_trip() {
    BOOST_TEST_EQ(pem::public_key_label, "PUBLIC KEY");
    BOOST_TEST_EQ(pem::private_key_label, "PRIVATE KEY");
    auto const pair = rfc6979_pair();
    auto const key = pair.public_key();
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const public_encoding = spki(*key);
    auto const public_text = armoured(pem::public_key_label, public_encoding);
    BOOST_TEST(public_text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    BOOST_TEST(public_text.ends_with("\n-----END PUBLIC KEY-----\n"));
    auto const public_back = unarmoured(pem::public_key_label, public_text);
    BOOST_TEST(public_back == public_encoding);
    auto const decoded_key = p256::decode_spki(public_back);
    BOOST_TEST(decoded_key.has_value() && decoded_key->uncompressed() == data::rfc6979_public);

    auto const private_encoding = pkcs8(pair);
    auto const private_text = armoured(pem::private_key_label, private_encoding);
    BOOST_TEST(private_text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    BOOST_TEST(private_text.ends_with("\n-----END PRIVATE KEY-----\n"));
    auto const private_back = unarmoured(pem::private_key_label, private_text);
    BOOST_TEST(private_back == private_encoding);
    auto const decoded_pair = p256::decode_pkcs8(private_back);
    if (BOOST_TEST(decoded_pair.has_value())) {
        BOOST_TEST(std::ranges::equal(scalar_of(*decoded_pair), data::rfc6979_scalar));
        BOOST_TEST(std::ranges::equal(point_of(*decoded_pair), data::rfc6979_public));
    }
}

#ifdef WEBCPP_TEST_WYCHEPROOF
namespace json = boost::json;

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

// The flags of an acceptable case that decode_spki may refuse, each with its reason. Every case
// that carries one of the explicit-parameter flags also carries UnnamedCurve.
std::map<std::string, std::string_view, std::less<>> const& listed_flags() {
    constexpr std::string_view compressed_point =
        "a compressed point: BearSSL decodes uncompressed points alone, D36";
    constexpr std::string_view not_der =
        "not the one DER encoding encode_spki writes: the strict rule refuses it, D30";
    constexpr std::string_view unnamed =
        "explicit curve parameters, not secp256r1's OID: re-encoding gives other bytes, D30";
    constexpr std::string_view parameter =
        "explicit curve parameters, with UnnamedCurve: refused as it, D30";
    static std::map<std::string, std::string_view, std::less<>> const listed{
        {"CompressedPublic", compressed_point},
        {"CompressedPoint", compressed_point},
        {"InvalidAsn", not_der},
        {"UnnamedCurve", unnamed},
        {"UnusedParam", parameter},
        {"WrongOrder", parameter},
        {"ModifiedGenerator", parameter},
        {"ModifiedCofactor", parameter},
        {"NoCofactor", parameter},
        {"ModifiedCurveParameter", parameter},
    };
    return listed;
}

// The counts of the file.
struct counts {
    /** Cases run. */
    int total = 0;
    /** Valid cases whose x agreed. */
    int valid_agreed = 0;
    /** Invalid cases refused by decode_spki. */
    int invalid_refused_decoding = 0;
    /** Invalid cases refused after it, by keypair::from_secret or agree. */
    int invalid_refused_after = 0;
    /** Acceptable cases whose x agreed. */
    int acceptable_agreed = 0;
    /** Acceptable cases refused by decode_spki, for a listed flag. */
    int acceptable_refused = 0;
    /** The listed refusals by flag (a case counts under each of its flags). */
    std::map<std::string, int, std::less<>> by_flag;
    /** The listed refusals by the one reason chosen for each case, as the page states them. */
    int refused_compressed = 0;
    int refused_not_der = 0;
    int refused_explicit_parameters = 0;
};

// A case's private key as 32 bytes: Wycheproof writes it as an ASN.1 integer's bytes, which may
// carry a leading 00; the leading zero bytes are stripped and the rest left-padded. More than 32
// significant bytes is no P-256 scalar: nothing is returned.
bytes scalar_bytes(bytes const& integer) {
    auto const first = std::ranges::find_if(integer, [](std::uint8_t b) { return b != 0; });
    bytes const significant(first, integer.end());
    if (significant.size() > 32) {
        return {};
    }
    bytes padded(32 - significant.size(), 0);
    padded.insert(padded.end(), significant.begin(), significant.end());
    return padded;
}

// Reports a case that went wrong, by its number.
void report(json::value const& t, std::string_view what) {
    std::string message = "ecdh_secp256r1_test tcId ";
    message += std::to_string(t.at("tcId").to_number<std::int64_t>());
    message += ": ";
    message += what;
    BOOST_ERROR(message.c_str());
}

// The case's ECDH with a key decoded from its SPKI, or the error of the step that refused it:
// keypair::from_secret or agree (decode_spki's refusal is the caller's).
boost::system::result<crypto::secret<32>> derive(json::value const& t, public_key const& peer) {
    auto const scalar = scalar_bytes(test::from_hex(str(t.at("private"))));
    if (scalar.empty()) {
        return error::invalid_secret_key;
    }
    auto const pair = keypair::from_secret(scalar);
    if (!pair) {
        return pair.error();
    }
    return pair->agree(peer);
}

// An acceptable case that decode_spki refused: expected when one of its flags is listed, printed
// with its reason; any other fails.
void listed_refusal(json::value const& t, counts& seen) {
    std::string flags;
    std::string_view reason;
    for (auto const& f : t.at("flags").as_array()) {
        auto const flag = str(f);
        flags += flags.empty() ? flag : "," + flag;
        if (auto const found = listed_flags().find(flag); found != listed_flags().end()) {
            ++seen.by_flag[flag];
            if (reason.empty() || flag == "UnnamedCurve" || flag.starts_with("Compressed")) {
                reason = found->second;
            }
        }
    }
    if (reason.empty()) {
        report(t, "acceptable case refused by decode_spki, with no listed flag: " + flags);
        return;
    }
    ++seen.acceptable_refused;
    if (reason.starts_with("a compressed point")) {
        ++seen.refused_compressed;
    } else if (reason.starts_with("not the one DER")) {
        ++seen.refused_not_der;
    } else {
        ++seen.refused_explicit_parameters;
    }
    std::cout << "ecdh_secp256r1_test tcId " << t.at("tcId").to_number<std::int64_t>()
              << " acceptable (" << flags << "), refused by decode_spki: " << reason << '\n';
}

// One case: an invalid one is refused by decode_spki or after it; a valid one decodes and agrees
// with its shared x; an acceptable one agrees, or is refused by decode_spki for a listed flag.
void spki_case(json::value const& t, counts& seen) {
    ++seen.total;
    auto const verdict = str(t.at("result"));
    auto const decoded = p256::decode_spki(test::from_hex(str(t.at("public"))));
    if (decoded.has_error() && decoded.error() != error::invalid_encoding) {
        report(t, "decode_spki refused with another error than invalid_encoding");
        return;
    }
    if (verdict == "invalid") {
        if (decoded.has_error()) {
            ++seen.invalid_refused_decoding;
        } else if (derive(t, *decoded).has_error()) {
            ++seen.invalid_refused_after;
        } else {
            report(t, "invalid case derived a shared x");
        }
        return;
    }
    if (verdict != "valid" && verdict != "acceptable") {
        report(t, verdict + ", not expected");
        return;
    }
    if (decoded.has_error()) {
        if (verdict == "valid") {
            report(t, "valid case refused by decode_spki");
        } else {
            listed_refusal(t, seen);
        }
        return;
    }
    auto const derived = derive(t, *decoded);
    auto const shared = test::from_hex(str(t.at("shared")));
    if (!derived.has_value() || !std::ranges::equal(derived->bytes(), shared)) {
        report(t, verdict + " case refused or disagreed");
        return;
    }
    ++(verdict == "valid" ? seen.valid_agreed : seen.acceptable_agreed);
}

// Wycheproof's ECDH on P-256 with the peer's key as SPKI DER, every case through spki_case.
void wycheproof_spki() {
    auto const text =
        test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/ecdh_secp256r1_test.json");
    boost::system::error_code ec;
    auto const doc = json::parse(text, ec);
    if (!BOOST_TEST(!ec)) {
        return;
    }
    counts seen;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            spki_case(t, seen);
        }
    }
    std::cout << "ecdh_secp256r1_test: tests=" << seen.total
              << " valid_agreed=" << seen.valid_agreed
              << " invalid_refused_by_decode_spki=" << seen.invalid_refused_decoding
              << " invalid_refused_after=" << seen.invalid_refused_after
              << " acceptable_agreed=" << seen.acceptable_agreed
              << " acceptable_refused_listed=" << seen.acceptable_refused << '\n';
    for (auto const& [flag, count] : seen.by_flag) {
        std::cout << "  listed " << flag << ": " << count << '\n';
    }
    BOOST_TEST_EQ(seen.total, 612);
    BOOST_TEST_EQ(seen.valid_agreed, 330);
    // Every invalid case is a defect of its SPKI, refused where it is decoded.
    BOOST_TEST_EQ(seen.invalid_refused_decoding, 52);
    BOOST_TEST_EQ(seen.invalid_refused_after, 0);
    // Every acceptable case is a form the strict rule refuses: a compressed point, an encoding
    // that is not DER's one, or explicit curve parameters.
    BOOST_TEST_EQ(seen.acceptable_agreed, 0);
    BOOST_TEST_EQ(seen.acceptable_refused, 230);
    // The page's breakdown of those 230, by the reason chosen for each case.
    BOOST_TEST_EQ(seen.refused_compressed, 1);
    BOOST_TEST_EQ(seen.refused_not_der, 222);
    BOOST_TEST_EQ(seen.refused_explicit_parameters, 7);
}
#endif

}  // namespace

int main() {
    constants();
    round_trips();
    bearssl_writes_the_same();
    refusals();
    pem_round_trip();
#ifdef WEBCPP_TEST_WYCHEPROOF
    wycheproof_spki();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
