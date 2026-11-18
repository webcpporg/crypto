// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's keys in files: RFC 5480's SPKI in both point forms and PKCS#8 with RFC 5915's
// ECPrivateKey, strict, and PEM around both (pem::armour and pem::unarmour, on libsodium). The
// constants equal the DER a small builder writes here from the ASN.1; 64 seeded key pairs
// round-trip, as DER and as PEM; Wycheproof's 752 SPKIs of its ECDH vectors decode exactly where
// version 0.1's parser takes their point (WEBCPP_TEST_WYCHEPROOF); every malformed input, DER or
// PEM, is invalid_encoding, and a refusal writes nothing. The outside oracles: OpenSSL's keys,
// encodings and PEM text (WEBCPP_TEST_OPENSSL_ORACLE: natively and on WASI), and node's crypto
// module under Emscripten.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#ifdef WEBCPP_TEST_WYCHEPROOF
#include "support/test_data.hpp"

#include <boost/json.hpp>
#endif

#ifdef WEBCPP_TEST_OPENSSL_ORACLE
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#ifdef __EMSCRIPTEN__
#include <emscripten/em_js.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace pem = webcpp::crypto::pem;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;

namespace {

using bytes = std::vector<std::uint8_t>;

static_assert(secp::spki_compressed_size == 56);
static_assert(secp::spki_uncompressed_size == 88);
static_assert(secp::max_spki_size == 88);
static_assert(secp::max_pkcs8_size == 135);
static_assert(crypto::detail::secp256k1_spki_compressed_prefix.size() + 33 ==
              secp::spki_compressed_size);
static_assert(crypto::detail::secp256k1_spki_uncompressed_prefix.size() + 65 ==
              secp::spki_uncompressed_size);
static_assert(crypto::detail::secp256k1_pkcs8_prefix.size() + 32 +
                  crypto::detail::secp256k1_pkcs8_infix.size() + 65 ==
              secp::max_pkcs8_size);
static_assert(std::is_same_v<decltype(secp::decode_pkcs8(std::declval<bytes const&>())),
                             boost::system::result<secp::keypair>>);

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

// The OIDs' contents: id-ecPublicKey (1.2.840.10045.2.1), secp256k1 (1.3.132.0.10) and P-256
// (1.2.840.10045.3.1.7).
bytes ec_public_key_oid() {
    return test::from_hex("2a8648ce3d0201");
}

bytes secp256k1_oid() {
    return test::from_hex("2b8104000a");
}

bytes p256_oid() {
    return test::from_hex("2a8648ce3d030107");
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

struct ec_private_key {
    std::uint8_t version = 1;
    bytes secret;
    bool parameters = false;
    bytes point;  // none when empty
};

bytes encoded(ec_private_key const& key) {
    bytes content = cat({der(0x02, {key.version}), der(0x04, key.secret)});
    if (key.parameters) {
        content = cat({content, der(0xa0, der(0x06, secp256k1_oid()))});
    }
    if (!key.point.empty()) {
        content = cat({content, der(0xa1, bit_string(key.point))});
    }
    return der(0x30, content);
}

bytes pkcs8_of(std::uint8_t version, bytes const& curve, ec_private_key const& key) {
    return der(0x30, cat({der(0x02, {version}), algorithm(curve), der(0x04, encoded(key))}));
}

// A key pair from the generator: a secret make refuses is drawn again.
std::pair<secp::keypair, bytes> draw(std::mt19937_64& generator) {
    for (;;) {
        bytes secret(32);
        for (auto& octet : secret) {
            octet = static_cast<std::uint8_t>(generator());
        }
        auto made = secp::keypair::make(secret);
        if (made) {
            return {std::move(*made), secret};
        }
    }
}

secp::public_key public_of(secp::keypair const& key) {
    auto const encoded_key = key.public_key();
    auto const parsed = secp::parse_public_key(*encoded_key);
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

bytes uncompressed_of(secp::keypair const& key) {
    auto const point = key.public_key_uncompressed();
    return {point->begin(), point->end()};
}

bytes compressed_of(secp::keypair const& key) {
    auto const point = key.public_key();
    return {point->begin(), point->end()};
}

bytes spki(secp::public_key const& key, secp::point_form form) {
    std::array<std::uint8_t, secp::max_spki_size> out{};
    auto const size = secp::encode_spki(key, out, form);
    if (!BOOST_TEST(size.has_value())) {
        return {};
    }
    return {out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*size)};
}

bytes pkcs8(secp::keypair const& key) {
    std::array<std::uint8_t, secp::max_pkcs8_size> out{};
    auto const size = secp::encode_pkcs8(key, out);
    if (!BOOST_TEST(size.has_value())) {
        return {};
    }
    return {out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*size)};
}

// DER as PEM under a label, of exactly the size armoured_size gives.
std::string armoured(std::string_view label, bytes const& der) {
    std::string text(pem::armoured_size(label.size(), der.size()), '\0');
    auto const written = pem::armour(label, der, text);
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

// The constants are the DER the builder writes.
void constants() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xf0a3a75ULL);
    auto const [key, secret] = draw(generator);
    auto const compressed = compressed_of(key);
    auto const uncompressed = uncompressed_of(key);
    BOOST_TEST_EQ(test::to_hex(spki(public_of(key), secp::point_form::compressed)),
                  test::to_hex(spki_of(secp256k1_oid(), compressed)));
    BOOST_TEST_EQ(test::to_hex(spki(public_of(key), secp::point_form::uncompressed)),
                  test::to_hex(spki_of(secp256k1_oid(), uncompressed)));
    BOOST_TEST_EQ(
        test::to_hex(pkcs8(key)),
        test::to_hex(pkcs8_of(
            0, secp256k1_oid(),
            {.version = 1, .secret = secret, .parameters = false, .point = uncompressed})));
    // The default form is compressed.
    std::array<std::uint8_t, secp::max_spki_size> out{};
    auto const size = secp::encode_spki(public_of(key), out);
    BOOST_TEST(size && *size == secp::spki_compressed_size);
}

// One key pair's SPKI in `form` decodes to its key and encodes again to the same bytes.
void spki_round_trip(secp::public_key const& expected, secp::point_form form) {
    auto const encoding = spki(expected, form);
    BOOST_TEST_EQ(encoding.size(), form == secp::point_form::compressed
                                       ? secp::spki_compressed_size
                                       : secp::spki_uncompressed_size);
    auto const decoded = secp::decode_spki(encoding);
    if (BOOST_TEST(decoded.has_value())) {
        BOOST_TEST(*decoded == expected);
        BOOST_TEST(spki(*decoded, form) == encoding);
    }
}

// One key pair's PKCS#8 holds its secret, decodes to a key pair of the same key that signs as
// the original does, and encodes again to the same bytes.
void pkcs8_round_trip(secp::keypair const& key, bytes const& secret) {
    auto const private_encoding = pkcs8(key);
    BOOST_TEST_EQ(private_encoding.size(), secp::max_pkcs8_size);
    BOOST_TEST(std::ranges::equal(std::span(private_encoding).subspan(33, 32), secret));
    auto const decoded = secp::decode_pkcs8(private_encoding);
    if (!BOOST_TEST(decoded.has_value())) {
        return;
    }
    BOOST_TEST(public_of(*decoded) == public_of(key));
    BOOST_TEST(pkcs8(*decoded) == private_encoding);
    std::array<std::uint8_t, 32> const hash{1, 2, 3};
    BOOST_TEST(decoded->sign_ecdsa(hash).value() == key.sign_ecdsa(hash).value());
}

// One key pair's SPKI in both forms and its PKCS#8, armoured as PEM under their labels: the text
// unarmours to the same DER, which decodes to the same key.
void pem_round_trip(secp::keypair const& key) {
    for (auto const form : {secp::point_form::compressed, secp::point_form::uncompressed}) {
        auto const encoding = spki(public_of(key), form);
        auto const text = armoured(pem::public_key_label, encoding);
        BOOST_TEST(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        BOOST_TEST(text.ends_with("\n-----END PUBLIC KEY-----\n"));
        auto const back = unarmoured(pem::public_key_label, text);
        BOOST_TEST(back == encoding);
        auto const decoded = secp::decode_spki(back);
        BOOST_TEST(decoded.has_value() && *decoded == public_of(key));
    }
    auto const private_encoding = pkcs8(key);
    auto const text = armoured(pem::private_key_label, private_encoding);
    BOOST_TEST(text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    auto const back = unarmoured(pem::private_key_label, text);
    BOOST_TEST(back == private_encoding);
    auto const decoded = secp::decode_pkcs8(back);
    BOOST_TEST(decoded.has_value() && public_of(*decoded) == public_of(key));
}

// 64 seeded key pairs, each SPKI in both forms and each PKCS#8, as DER and as PEM.
void round_trips() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x5b1c0de5ULL);
    for (int round = 0; round < 64; ++round) {
        auto const [key, secret] = draw(generator);
        spki_round_trip(public_of(key), secp::point_form::compressed);
        spki_round_trip(public_of(key), secp::point_form::uncompressed);
        pkcs8_round_trip(key, secret);
        pem_round_trip(key);
    }
}

// An encoder that refuses writes nothing: a short buffer, a moved-from key pair.
// NOLINTBEGIN(bugprone-use-after-move)
void encoder_refusals() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xe2c0de2ULL);
    auto [key, secret] = draw(generator);
    auto const parsed = public_of(key);
    std::array<std::uint8_t, secp::max_pkcs8_size> out{};
    out.fill(0xa5);
    auto const untouched = [&out] {
        return std::ranges::all_of(out, [](std::uint8_t b) { return b == 0xa5; });
    };
    for (auto const form : {secp::point_form::compressed, secp::point_form::uncompressed}) {
        auto const refused =
            secp::encode_spki(parsed, std::span(out).first(secp::max_spki_size - 1), form);
        BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_input_size);
    }
    auto const short_pkcs8 =
        secp::encode_pkcs8(key, std::span(out).first(secp::max_pkcs8_size - 1));
    BOOST_TEST(short_pkcs8.has_error() && short_pkcs8.error() == crypto::error::invalid_input_size);
    BOOST_TEST(untouched());
    secp::keypair const moved = std::move(key);
    auto const empty = secp::encode_pkcs8(key, out);
    BOOST_TEST(empty.has_error() && empty.error() == crypto::error::invalid_state);
    BOOST_TEST(untouched());
    BOOST_TEST(secp::encode_pkcs8(moved, out).has_value());
}

// NOLINTEND(bugprone-use-after-move)

void refused_spki(std::string const& label, bytes const& encoding) {
    auto const decoded = secp::decode_spki(encoding);
    if (!BOOST_TEST(decoded.has_error()) ||
        !BOOST_TEST(decoded.error() == crypto::error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
}

void refused_pkcs8(std::string const& label, bytes const& encoding) {
    auto const decoded = secp::decode_pkcs8(encoding);
    if (!BOOST_TEST(decoded.has_error()) ||
        !BOOST_TEST(decoded.error() == crypto::error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
}

// The group order n.
bytes order() {
    return test::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
}

// Every malformed input is invalid_encoding.
void malformed() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0xbad0de5ULL);
    auto const [key, secret] = draw(generator);
    auto const [other, other_secret] = draw(generator);
    auto const compressed = compressed_of(key);
    auto const uncompressed = uncompressed_of(key);
    auto const good_compressed = spki_of(secp256k1_oid(), compressed);
    auto const good_uncompressed = spki_of(secp256k1_oid(), uncompressed);
    auto const good_pkcs8 =
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = secret, .parameters = false, .point = uncompressed});
    BOOST_TEST(secp::decode_spki(good_compressed).has_value());
    BOOST_TEST(secp::decode_spki(good_uncompressed).has_value());
    BOOST_TEST(secp::decode_pkcs8(good_pkcs8).has_value());

    refused_spki("empty", {});
    refused_spki("prefix alone", spki_of(secp256k1_oid(), {}));
    refused_spki("P-256's OID, uncompressed", spki_of(p256_oid(), uncompressed));
    refused_spki("P-256's OID, compressed", spki_of(p256_oid(), compressed));
    refused_spki("trailing byte", cat({good_uncompressed, {0x00}}));
    refused_spki("trailing byte, compressed", cat({good_compressed, {0x00}}));
    refused_spki("truncated", bytes(good_uncompressed.begin(), good_uncompressed.end() - 1));
    // 30 81 56 ...: the outer length in long form, which DER forbids for a length below 128.
    refused_spki(
        "long-form length",
        cat({{0x30, 0x81, 0x56}, bytes(good_uncompressed.begin() + 2, good_uncompressed.end())}));
    // A point of the other form under each prefix, the lengths left as the prefix says.
    refused_spki(
        "compressed point, uncompressed prefix",
        cat({bytes(good_uncompressed.begin(), good_uncompressed.begin() + 23), compressed}));
    refused_spki("uncompressed point, compressed prefix",
                 cat({bytes(good_compressed.begin(), good_compressed.begin() + 23), uncompressed}));
    // X9.62's hybrid prefixes, 06 and 07, with the point's own parity: a valid point.
    auto hybrid = uncompressed;
    hybrid[0] = static_cast<std::uint8_t>(0x06U | (uncompressed[64] & 1U));
    refused_spki("hybrid prefix", spki_of(secp256k1_oid(), hybrid));
    hybrid[0] ^= 1U;
    refused_spki("hybrid prefix, wrong parity", spki_of(secp256k1_oid(), hybrid));
    // A point off the curve, and an x with no y.
    auto off_curve = uncompressed;
    off_curve[64] ^= 1U;
    refused_spki("off the curve", spki_of(secp256k1_oid(), off_curve));
    bytes no_y(33);
    no_y[0] = 0x02;
    no_y[32] = 0x05;  // x = 5 is no point's x
    refused_spki("x with no y", spki_of(secp256k1_oid(), no_y));
    // The BIT STRING's unused-bits byte not zero.
    auto unused_bits = good_uncompressed;
    unused_bits[22] = 0x01;
    refused_spki("unused bits", unused_bits);

    refused_pkcs8("empty", {});
    refused_pkcs8(
        "P-256's OID",
        pkcs8_of(0, p256_oid(),
                 {.version = 1, .secret = secret, .parameters = false, .point = uncompressed}));
    refused_pkcs8("trailing byte", cat({good_pkcs8, {0x00}}));
    refused_pkcs8("truncated", bytes(good_pkcs8.begin(), good_pkcs8.end() - 1));
    // OpenSSL's -nopubkey form: no [1] publicKey.
    refused_pkcs8("no public key",
                  pkcs8_of(0, secp256k1_oid(),
                           {.version = 1, .secret = secret, .parameters = false, .point = {}}));
    // The curve's OID again in ECPrivateKey's [0] parameters.
    refused_pkcs8(
        "[0] parameters",
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = secret, .parameters = true, .point = uncompressed}));
    // OneAsymmetricKey version 2 (the value 1).
    refused_pkcs8(
        "version 1",
        pkcs8_of(1, secp256k1_oid(),
                 {.version = 1, .secret = secret, .parameters = false, .point = uncompressed}));
    refused_pkcs8(
        "ECPrivateKey version 0",
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 0, .secret = secret, .parameters = false, .point = uncompressed}));
    // The public key of another secret.
    refused_pkcs8("another key's public key", pkcs8_of(0, secp256k1_oid(),
                                                       {
                                                           .version = 1,
                                                           .secret = secret,
                                                           .parameters = false,
                                                           .point = uncompressed_of(other),
                                                       }));
    // The secret's own public key, compressed: OpenSSL's form for a key set to compressed, 102
    // bytes, whose outer length fits the short form.
    auto const compressed_inside =
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = secret, .parameters = false, .point = compressed});
    BOOST_TEST_EQ(compressed_inside.size(), 102U);
    refused_pkcs8("compressed public key", compressed_inside);
    // A public key off the curve.
    refused_pkcs8(
        "public key off the curve",
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = secret, .parameters = false, .point = off_curve}));
    // A secret of zero, and one equal to the group order.
    refused_pkcs8(
        "zero secret",
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = bytes(32), .parameters = false, .point = uncompressed}));
    refused_pkcs8(
        "order-sized secret",
        pkcs8_of(0, secp256k1_oid(),
                 {.version = 1, .secret = order(), .parameters = false, .point = uncompressed}));
    // The outer length, 132, takes the long form 81 84; the longer 82 00 84 is not DER.
    refused_pkcs8("non-minimal long form",
                  cat({{0x30, 0x82, 0x00, 0x84}, bytes(good_pkcs8.begin() + 3, good_pkcs8.end())}));
}

// PEM text refused with invalid_encoding, the output untouched.
void refused_pem(std::string const& label, std::string_view expected_label, std::string_view text) {
    std::array<std::uint8_t, 256> out{};
    out.fill(0xa5);
    auto const read = pem::unarmour(expected_label, text, out);
    if (!BOOST_TEST(read.has_error()) ||
        !BOOST_TEST(read.error() == crypto::error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
    BOOST_TEST(std::ranges::all_of(out, [](std::uint8_t b) { return b == 0xa5; }));
}

// Text with every `from` replaced by `to`.
std::string replaced(std::string text, std::string_view from, std::string_view to) {
    for (std::size_t at = text.find(from); at != std::string::npos;
         at = text.find(from, at + to.size())) {
        text.replace(at, from.size(), to);
    }
    return text;
}

// PEM that is not exactly what pem::armour writes for the label expected is invalid_encoding:
// another label, a line of 63 characters, a carriage return.
void malformed_pem() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x9e3de5ULL);
    auto const [key, secret] = draw(generator);
    auto const public_text =
        armoured(pem::public_key_label, spki(public_of(key), secp::point_form::uncompressed));
    auto const private_text = armoured(pem::private_key_label, pkcs8(key));
    BOOST_TEST(!unarmoured(pem::public_key_label, public_text).empty());
    BOOST_TEST(!unarmoured(pem::private_key_label, private_text).empty());

    refused_pem("PRIVATE KEY read as PUBLIC KEY", pem::public_key_label, private_text);
    refused_pem("PUBLIC KEY read as PRIVATE KEY", pem::private_key_label, public_text);
    refused_pem("EC PRIVATE KEY", pem::private_key_label,
                replaced(private_text, "PRIVATE KEY", "EC PRIVATE KEY"));
    refused_pem("END under another label", pem::public_key_label,
                replaced(public_text, "END PUBLIC KEY", "END PRIVATE KEY"));
    // The first line of base64 one character short: 63 characters, then a line feed.
    std::size_t const first_line = std::string_view("-----BEGIN PRIVATE KEY-----\n").size();
    auto short_line = private_text;
    short_line.erase(first_line + 63, 1);
    refused_pem("a line of 63 characters", pem::private_key_label, short_line);
    auto short_public_line = public_text;
    short_public_line.erase(first_line - 1 + 63, 1);
    refused_pem("a line of 63 characters, SPKI", pem::public_key_label, short_public_line);
    // Line feeds preceded by carriage returns, every one, and the last line's alone.
    refused_pem("carriage returns", pem::private_key_label, replaced(private_text, "\n", "\r\n"));
    auto last_return = public_text;
    last_return.insert(last_return.size() - 1, "\r");
    refused_pem("a carriage return on the last line", pem::public_key_label, last_return);
}

#ifdef WEBCPP_TEST_WYCHEPROOF
struct wycheproof_counts {
    int total = 0;
    int taken = 0;
    int other = 0;
    int decoded = 0;
    int refused = 0;
};

// One SPKI of the file: refused unless it is in one of the two forms and its point parses
// with version 0.1's parser; decoded, it encodes again to the same bytes.
void wycheproof_case(std::string const& label, std::string_view hex, wycheproof_counts& counts) {
    constexpr std::string_view uncompressed_prefix =
        "3056301006072a8648ce3d020106052b8104000a034200";
    constexpr std::string_view compressed_prefix = "3036301006072a8648ce3d020106052b8104000a032200";
    ++counts.total;
    auto const encoding = test::from_hex(hex);
    auto const result = secp::decode_spki(encoding);
    bool const uncompressed = hex.size() == std::size_t{2} * secp::spki_uncompressed_size &&
                              hex.starts_with(uncompressed_prefix);
    bool const compressed = hex.size() == std::size_t{2} * secp::spki_compressed_size &&
                            hex.starts_with(compressed_prefix);
    secp256k1_pubkey point{};
    bool const parses = (uncompressed || compressed) && crypto::detail::secp256k1_parse_public_key(
                                                            std::span(encoding).subspan(23), point);
    if (!uncompressed && !compressed) {
        ++counts.other;
    } else {
        ++counts.taken;
        ++(parses ? counts.decoded : counts.refused);
    }
    if (parses) {
        auto const form =
            compressed ? secp::point_form::compressed : secp::point_form::uncompressed;
        if (!BOOST_TEST(result.has_value()) || !BOOST_TEST(spki(*result, form) == encoding)) {
            BOOST_ERROR(label.c_str());
        }
    } else if (!BOOST_TEST(result.has_error() &&
                           result.error() == crypto::error::invalid_encoding)) {
        BOOST_ERROR(label.c_str());
    }
}

// Wycheproof's ECDH vectors carry each peer key as an SPKI: the 496 in either of the two forms
// version 0.1's test takes decode exactly where version 0.1's parser takes their point, and the
// other 256 (other curves' parameters, other encodings, the hybrid form) are refused.
void wycheproof() {
    auto const text =
        test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/ecdh_secp256k1_test.json");
    boost::system::error_code ec;
    auto const doc = boost::json::parse(text, ec);
    if (!BOOST_TEST(!ec)) {
        return;
    }
    wycheproof_counts counts;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            wycheproof_case("tcId " + std::to_string(t.at("tcId").to_number<std::int64_t>()),
                            std::string_view(t.at("public").as_string()), counts);
        }
    }
    std::cout << "wycheproof spki: total=" << counts.total << " taken=" << counts.taken
              << " decoded=" << counts.decoded << " refused_point=" << counts.refused
              << " refused_other=" << counts.other << '\n';
    BOOST_TEST_EQ(counts.total, 752);
    BOOST_TEST_EQ(counts.taken, 496);
    BOOST_TEST_EQ(counts.other, 256);
    BOOST_TEST_EQ(counts.decoded, 474);
    BOOST_TEST_EQ(counts.refused, 22);
}
#endif

#ifdef WEBCPP_TEST_OPENSSL_ORACLE
bytes openssl_pkcs8(EVP_PKEY const* key) {
    // NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's macro ors signed constants
    int const selection = EVP_PKEY_KEYPAIR;
    OSSL_ENCODER_CTX* context =
        OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER", "PrivateKeyInfo", nullptr);
    unsigned char* data = nullptr;
    std::size_t size = 0;
    bytes out;
    if (BOOST_TEST(context != nullptr) &&
        BOOST_TEST(OSSL_ENCODER_to_data(context, &data, &size) == 1)) {
        out.assign(data, data + size);
    }
    OPENSSL_free(data);
    OSSL_ENCODER_CTX_free(context);
    return out;
}

bytes openssl_spki(EVP_PKEY const* key) {
    int const size = i2d_PUBKEY(key, nullptr);
    if (!BOOST_TEST(size > 0)) {
        return {};
    }
    bytes out(static_cast<std::size_t>(size));
    unsigned char* cursor = out.data();
    BOOST_TEST_EQ(i2d_PUBKEY(key, &cursor), size);
    return out;
}

// OpenSSL's PEM of a key: its SPKI with PEM_write_bio_PUBKEY, or its PKCS#8 with
// PEM_write_bio_PrivateKey (no cipher), each in the key's current point form.
std::string openssl_pem(EVP_PKEY const* key, bool private_key) {
    BIO* bio = BIO_new(BIO_s_mem());
    std::string out;
    if (BOOST_TEST(bio != nullptr) &&
        BOOST_TEST((private_key
                        ? PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr)
                        : PEM_write_bio_PUBKEY(bio, key)) == 1)) {
        char* data = nullptr;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast): OpenSSL's macro casts
        long const size = BIO_get_mem_data(bio, &data);
        if (BOOST_TEST(size > 0)) {
            out.assign(data, static_cast<std::size_t>(size));
        }
    }
    BIO_free(bio);
    return out;
}

// webcpp's SPKI read by OpenSSL is the key it came from.
void openssl_reads_spki(EVP_PKEY const* key, bytes const& encoding) {
    unsigned char const* cursor = encoding.data();
    EVP_PKEY* read = d2i_PUBKEY(nullptr, &cursor, static_cast<long>(encoding.size()));
    BOOST_TEST(read != nullptr && EVP_PKEY_eq(read, key) == 1);
    BOOST_TEST(cursor == encoding.data() + encoding.size());
    EVP_PKEY_free(read);
}

// OpenSSL's key in its default uncompressed form: webcpp decodes its PKCS#8 and SPKI and encodes
// the same bytes, and OpenSSL reads webcpp's encodings back to the same key.
void openssl_default_form(EVP_PKEY const* key) {
    auto const private_encoding = openssl_pkcs8(key);
    auto const uncompressed = openssl_spki(key);
    BOOST_TEST_EQ(private_encoding.size(), secp::max_pkcs8_size);
    BOOST_TEST_EQ(uncompressed.size(), secp::spki_uncompressed_size);
    auto const pair = secp::decode_pkcs8(private_encoding);
    auto const from_uncompressed = secp::decode_spki(uncompressed);
    if (!BOOST_TEST(pair.has_value()) || !BOOST_TEST(from_uncompressed.has_value())) {
        return;
    }
    BOOST_TEST(pkcs8(*pair) == private_encoding);
    BOOST_TEST(spki(*from_uncompressed, secp::point_form::uncompressed) == uncompressed);
    BOOST_TEST(public_of(*pair) == *from_uncompressed);
    auto const mine = pkcs8(*pair);
    unsigned char const* cursor = mine.data();
    EVP_PKEY* read = d2i_AutoPrivateKey(nullptr, &cursor, static_cast<long>(mine.size()));
    BOOST_TEST(read != nullptr && EVP_PKEY_eq(read, key) == 1);
    BOOST_TEST(read != nullptr && openssl_pkcs8(read) == private_encoding);
    EVP_PKEY_free(read);
    openssl_reads_spki(key, spki(*from_uncompressed, secp::point_form::uncompressed));
    openssl_reads_spki(key, spki(*from_uncompressed, secp::point_form::compressed));
    // OpenSSL's PEM text is pem::armour's, character for character, and unarmours to its DER.
    auto const public_text = openssl_pem(key, false);
    BOOST_TEST_EQ(public_text, armoured(pem::public_key_label, uncompressed));
    BOOST_TEST(unarmoured(pem::public_key_label, public_text) == uncompressed);
    auto const private_text = openssl_pem(key, true);
    BOOST_TEST(private_text == armoured(pem::private_key_label, mine));
    BOOST_TEST(unarmoured(pem::private_key_label, private_text) == private_encoding);
}

// The same key set to the compressed form: webcpp decodes OpenSSL's compressed SPKI and encodes
// the same bytes; OpenSSL now writes the compressed point into ECPrivateKey's [1] too, 102
// bytes, which webcpp refuses.
void openssl_compressed_form(EVP_PKEY* key) {
    BOOST_TEST(EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                              "compressed") == 1);
    auto const compressed = openssl_spki(key);
    BOOST_TEST_EQ(compressed.size(), secp::spki_compressed_size);
    auto const from_compressed = secp::decode_spki(compressed);
    if (BOOST_TEST(from_compressed.has_value())) {
        BOOST_TEST(spki(*from_compressed, secp::point_form::compressed) == compressed);
        openssl_reads_spki(key, spki(*from_compressed, secp::point_form::uncompressed));
        BOOST_TEST_EQ(
            openssl_pem(key, false),
            armoured(pem::public_key_label, spki(*from_compressed, secp::point_form::compressed)));
    }
    auto const compressed_private = openssl_pkcs8(key);
    BOOST_TEST_EQ(compressed_private.size(), 102U);
    auto const refused = secp::decode_pkcs8(compressed_private);
    BOOST_TEST(refused.has_error() && refused.error() == crypto::error::invalid_encoding);
}

// 64 keys OpenSSL makes, in both forms; OpenSSL's error queue is left empty.
void openssl_oracle() {
    for (int round = 0; round < 64; ++round) {
        EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "secp256k1");
        if (!BOOST_TEST(key != nullptr)) {
            break;
        }
        openssl_default_form(key);
        openssl_compressed_form(key);
        EVP_PKEY_free(key);
    }
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
}
#endif

#ifdef __EMSCRIPTEN__
// node's crypto module (synchronous: no JSPI): a PKCS#8 or an SPKI imported and exported again
// as DER. Each writes the bytes to `output` and returns their count, or -1 when node refused
// (the message goes to the console).
// clang-format off
EM_JS(int, node_pkcs8, (const std::uint8_t* input, std::size_t input_size, std::uint8_t* output), {
    try {
        const crypto = process.getBuiltinModule('node:crypto');
        const der = HEAPU8.slice(input, input + input_size);
        const key = crypto.createPrivateKey({key: der, format: 'der', type: 'pkcs8'});
        const back = new Uint8Array(key.export({format: 'der', type: 'pkcs8'}));
        HEAPU8.set(back, output);
        return back.length;
    } catch (e) {
        console.error("node pkcs8: " + e);
        return -1;
    }
});

EM_JS(int, node_spki, (const std::uint8_t* input, std::size_t input_size, std::uint8_t* output), {
    try {
        const crypto = process.getBuiltinModule('node:crypto');
        const der = HEAPU8.slice(input, input + input_size);
        const key = crypto.createPublicKey({key: der, format: 'der', type: 'spki'});
        const back = new Uint8Array(key.export({format: 'der', type: 'spki'}));
        HEAPU8.set(back, output);
        return back.length;
    } catch (e) {
        console.error("node spki: " + e);
        return -1;
    }
});

EM_JS(int, node_public_of, (const std::uint8_t* input, std::size_t input_size,
                            std::uint8_t* output), {
    try {
        const crypto = process.getBuiltinModule('node:crypto');
        const der = HEAPU8.slice(input, input + input_size);
        const key = crypto.createPrivateKey({key: der, format: 'der', type: 'pkcs8'});
        const back = new Uint8Array(
            crypto.createPublicKey(key).export({format: 'der', type: 'spki'}));
        HEAPU8.set(back, output);
        return back.length;
    } catch (e) {
        console.error("node public key: " + e);
        return -1;
    }
});
// clang-format on

template <class Call>
bytes through_node(Call call, bytes const& input) {
    std::array<std::uint8_t, 256> out{};
    int const size = call(input.data(), input.size(), out.data());
    if (!BOOST_TEST(size > 0)) {
        return {};
    }
    return {out.begin(), out.begin() + size};
}

// 64 seeded key pairs: node's crypto gives webcpp's PKCS#8 and both SPKIs back, and derives
// from the PKCS#8 the public key webcpp encodes.
void node_oracle() {
    std::mt19937_64 generator(0x0de0de5ULL);
    for (int round = 0; round < 64; ++round) {
        auto const [key, secret] = draw(generator);
        auto const private_encoding = pkcs8(key);
        auto const uncompressed = spki(public_of(key), secp::point_form::uncompressed);
        auto const compressed = spki(public_of(key), secp::point_form::compressed);
        BOOST_TEST(through_node(node_pkcs8, private_encoding) == private_encoding);
        BOOST_TEST(through_node(node_spki, uncompressed) == uncompressed);
        BOOST_TEST(through_node(node_spki, compressed) == compressed);
        BOOST_TEST(through_node(node_public_of, private_encoding) == uncompressed);
    }
}
#endif

}  // namespace

int main() {
    constants();
    round_trips();
    encoder_refusals();
    malformed();
    malformed_pem();
#ifdef WEBCPP_TEST_WYCHEPROOF
    wycheproof();
#endif
#ifdef WEBCPP_TEST_OPENSSL_ORACLE
    openssl_oracle();
#endif
#ifdef __EMSCRIPTEN__
    node_oracle();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
