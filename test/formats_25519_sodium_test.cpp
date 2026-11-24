// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 8410's SPKI and PKCS#8 for Ed25519 and X25519, and PEM, on libsodium (design D30): RFC
// 8410's own keys (sections 10.1 and 10.3) decoded and encoded again to the same text; round
// trips of random key pairs; and every malformed input refused with invalid_encoding with nothing
// written: Ed25519's OID under X25519 and the other way, a trailing byte, a length in long form,
// PKCS#8 version 2 with the public key, each byte of a prefix changed, a PEM label other than the
// expected, a line of 63 characters, a carriage return, and base64 that is not the one encoding;
// an output too small is invalid_input_size, with nothing written either.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace pem = webcpp::crypto::pem;
namespace test = webcpp::test;

namespace {

// RFC 8410 section 10.1: an Ed25519 public key's SPKI, in PEM.
constexpr std::string_view rfc8410_public =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PUBLIC KEY-----\n";
// RFC 8410 section 10.3: the PKCS#8 of the same key pair, version 1, the seed alone.
constexpr std::string_view rfc8410_private =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    "-----END PRIVATE KEY-----\n";
// RFC 8410 section 10.3: the same key pair's PKCS#8 version 2, with an attribute and the public
// key, which a strict decoder refuses (design D30).
constexpr std::string_view rfc8410_private_v2 =
    "-----BEGIN PRIVATE KEY-----\n"
    "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n"
    "Z9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PRIVATE KEY-----\n";
// The seed and the public key of RFC 8410's key pair.
constexpr std::string_view rfc8410_seed =
    "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842";
constexpr std::string_view rfc8410_public_key =
    "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1";

// The byte an output is filled with before a call, which a refusal must leave in every place.
constexpr std::uint8_t untouched = 0xa5;
constexpr char untouched_char = '#';

/** The bytes of a key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(std::span<std::uint8_t const> key) {
    return {key.begin(), key.end()};
}

/** Whether every byte of a buffer is still the sentinel. */
bool all_untouched(std::span<std::uint8_t const> out) {
    return std::ranges::all_of(out, [](std::uint8_t b) { return b == untouched; });
}

/** Whether every character of a buffer is still the sentinel. */
bool all_untouched(std::span<char const> out) {
    return std::ranges::all_of(out, [](char c) { return c == untouched_char; });
}

/** The DER of a PEM text, through pem::unarmour, or empty on a refusal (checked by the caller). */
std::vector<std::uint8_t> der_of(std::string_view label, std::string_view text) {
    std::vector<std::uint8_t> der(text.size());
    auto const written = pem::unarmour(label, text, der);
    BOOST_TEST(written.has_value());
    der.resize(written ? *written : 0);
    return der;
}

/** The PEM text of DER, through pem::armour. */
std::string text_of(std::string_view label, std::span<std::uint8_t const> der) {
    std::string text(pem::armoured_size(label.size(), der.size()), untouched_char);
    auto const written = pem::armour(label, der, text);
    BOOST_TEST(written.has_value());
    BOOST_TEST(written.has_value() && *written == text.size());
    return text;
}

/** An Ed25519 SPKI refused by decode_spki with invalid_encoding. */
void ed25519_spki_refused(std::vector<std::uint8_t> const& spki, char const* what) {
    auto const decoded = ed25519::decode_spki(spki);
    if (!BOOST_TEST(!decoded.has_value() && decoded.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "Ed25519 SPKI accepted: %s\n", what));
    }
}

/** An X25519 SPKI refused by decode_spki with invalid_encoding. */
void x25519_spki_refused(std::vector<std::uint8_t> const& spki, char const* what) {
    auto const decoded = x25519::decode_spki(spki);
    if (!BOOST_TEST(!decoded.has_value() && decoded.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "X25519 SPKI accepted: %s\n", what));
    }
}

/** An Ed25519 PKCS#8 refused by decode_pkcs8 with invalid_encoding. */
void ed25519_pkcs8_refused(std::vector<std::uint8_t> const& pkcs8, char const* what) {
    auto const decoded = ed25519::decode_pkcs8(pkcs8);
    if (!BOOST_TEST(!decoded.has_value() && decoded.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "Ed25519 PKCS#8 accepted: %s\n", what));
    }
}

/** An X25519 PKCS#8 refused by decode_pkcs8 with invalid_encoding. */
void x25519_pkcs8_refused(std::vector<std::uint8_t> const& pkcs8, char const* what) {
    auto const decoded = x25519::decode_pkcs8(pkcs8);
    if (!BOOST_TEST(!decoded.has_value() && decoded.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "X25519 PKCS#8 accepted: %s\n", what));
    }
}

/** A PEM text refused by unarmour with invalid_encoding, nothing written. */
void pem_refused(std::string_view label, std::string_view text, char const* what) {
    std::vector<std::uint8_t> out(text.size() + 64, untouched);
    auto const written = pem::unarmour(label, text, out);
    if (!BOOST_TEST(!written.has_value() && written.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "PEM accepted: %s\n", what));
    }
    BOOST_TEST(all_untouched(out));
}

/** The text with every occurrence of from replaced by to. */
std::string replaced(std::string_view text, std::string_view from, std::string_view to) {
    std::string out;
    std::size_t at = 0;
    for (auto found = text.find(from); found != std::string_view::npos;
         found = text.find(from, at)) {
        out.append(text.substr(at, found - at)).append(to);
        at = found + from.size();
    }
    out.append(text.substr(at));
    return out;
}

/** A PEM text whose body is wrapped at width characters instead of 64. */
std::string rewrapped(std::string_view text, std::size_t width) {
    auto const begin = text.find('\n') + 1;
    auto const end = text.rfind("-----END");
    std::string body;
    for (char const c : text.substr(begin, end - begin)) {
        if (c != '\n') {
            body += c;
        }
    }
    std::string out{text.substr(0, begin)};
    for (std::size_t at = 0; at < body.size(); at += width) {
        out.append(body.substr(at, width)).append("\n");
    }
    return out.append(text.substr(end));
}

void rfc8410_keys() {
    // Section 10.1: the SPKI's public key, and the SPKI encoded again to the same PEM.
    auto const spki = der_of(pem::public_key_label, rfc8410_public);
    BOOST_TEST_EQ(spki.size(), ed25519::max_spki_size);
    auto const public_key = ed25519::decode_spki(spki);
    BOOST_TEST(public_key.has_value());
    if (public_key) {
        BOOST_TEST(bytes_of(public_key->bytes()) == test::from_hex(rfc8410_public_key));
        std::array<std::uint8_t, ed25519::max_spki_size> encoded{};
        auto const written = ed25519::encode_spki(*public_key, encoded);
        BOOST_TEST(written.has_value() && *written == ed25519::max_spki_size);
        BOOST_TEST(text_of(pem::public_key_label, encoded) == rfc8410_public);
    }

    // Section 10.3: the PKCS#8's key pair, whose public key is section 10.1's and whose seed is
    // the RFC's, encoded again to the same PEM.
    auto const pkcs8 = der_of(pem::private_key_label, rfc8410_private);
    BOOST_TEST_EQ(pkcs8.size(), ed25519::max_pkcs8_size);
    BOOST_TEST(pkcs8.size() == 48 &&
               std::ranges::equal(std::span(pkcs8).last(32), test::from_hex(rfc8410_seed)));
    auto const key = ed25519::decode_pkcs8(pkcs8);
    BOOST_TEST(key.has_value());
    if (key) {
        auto const its_public = key->public_key();
        BOOST_TEST(its_public.has_value() &&
                   bytes_of(its_public->bytes()) == test::from_hex(rfc8410_public_key));
        std::array<std::uint8_t, ed25519::max_pkcs8_size> encoded{};
        auto const written = ed25519::encode_pkcs8(*key, encoded);
        BOOST_TEST(written.has_value() && *written == ed25519::max_pkcs8_size);
        BOOST_TEST(text_of(pem::private_key_label, encoded) == rfc8410_private);
    }

    // Section 10.3's version 2, with the public key: PEM that decodes, and a PKCS#8 refused.
    ed25519_pkcs8_refused(der_of(pem::private_key_label, rfc8410_private_v2),
                          "RFC 8410's version 2");
}

/** The constants of design D30: the 12 and 16 bytes before the key, for each curve. */
void layouts() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    std::string const key_hex = test::to_hex(key);
    std::array<std::uint8_t, 48> out{};
    auto written = ed25519::encode_spki(*ed25519::public_key::from_bytes(key), out);
    BOOST_TEST(written.has_value() && *written == 44);
    BOOST_TEST_EQ(test::to_hex(std::span(out).first(44)), "302a300506032b6570032100" + key_hex);
    written = x25519::encode_spki(key, out);
    BOOST_TEST(written.has_value() && *written == 44);
    BOOST_TEST_EQ(test::to_hex(std::span(out).first(44)), "302a300506032b656e032100" + key_hex);
    written = x25519::encode_pkcs8(key, out);
    BOOST_TEST(written.has_value() && *written == 48);
    BOOST_TEST_EQ(test::to_hex(out), "302e020100300506032b656e04220420" + key_hex);
    auto const pair = ed25519::keypair::from_secret(key);
    BOOST_TEST(pair.has_value());
    if (pair) {
        written = ed25519::encode_pkcs8(*pair, out);
        BOOST_TEST(written.has_value() && *written == 48);
        BOOST_TEST_EQ(test::to_hex(out), "302e020100300506032b657004220420" + key_hex);
    }
    static_assert(ed25519::max_spki_size == 44 && ed25519::max_pkcs8_size == 48);
    static_assert(x25519::max_spki_size == 44 && x25519::max_pkcs8_size == 48);
    static_assert(pem::armoured_size(10, 44) == 27 + 61 + 25);
    static_assert(pem::armoured_size(11, 48) == 28 + 65 + 26);
    static_assert(pem::armoured_size(11, 0) == 28 + 26);
}

/** A generated Ed25519 key pair through its SPKI, its PKCS#8 and their PEM, and back. */
void ed25519_round_trip() {
    std::array<std::uint8_t, 7> const message{'m', 'e', 's', 's', 'a', 'g', 'e'};
    auto const pair = ed25519::keypair::generate();
    BOOST_TEST(pair.has_value());
    if (!pair) {
        return;
    }
    auto const public_key = pair->public_key();
    BOOST_TEST(public_key.has_value());
    if (!public_key) {
        return;
    }
    std::array<std::uint8_t, ed25519::max_spki_size> spki{};
    BOOST_TEST(ed25519::encode_spki(*public_key, spki).has_value());
    auto const decoded_public = ed25519::decode_spki(spki);
    BOOST_TEST(decoded_public.has_value() && *decoded_public == *public_key);
    std::array<std::uint8_t, ed25519::max_pkcs8_size> pkcs8{};
    BOOST_TEST(ed25519::encode_pkcs8(*pair, pkcs8).has_value());
    auto const decoded = ed25519::decode_pkcs8(
        der_of(pem::private_key_label, text_of(pem::private_key_label, pkcs8)));
    BOOST_TEST(decoded.has_value());
    if (decoded) {
        BOOST_TEST(decoded->public_key().has_value() && *decoded->public_key() == *public_key);
        auto const signed_again = decoded->sign(crypto::eddsa, message);
        auto const signed_first = pair->sign(crypto::eddsa, message);
        BOOST_TEST(signed_again.has_value() && signed_first.has_value() &&
                   *signed_again == *signed_first);
    }
    BOOST_TEST(der_of(pem::public_key_label, text_of(pem::public_key_label, spki)) ==
               bytes_of(spki));
}

/** A drawn X25519 secret key through its SPKI and its PKCS#8, and back. */
void x25519_round_trip() {
    std::array<std::uint8_t, 32> secret_key{};
    BOOST_TEST(crypto::random_device().fill(secret_key).has_value());
    auto const x_key = x25519::keypair::from_secret(secret_key);
    if (!BOOST_TEST(x_key.has_value())) {
        return;
    }
    auto const x_public = x_key->public_key().value().bytes();
    std::array<std::uint8_t, x25519::max_spki_size> x_spki{};
    BOOST_TEST(x25519::encode_spki(x_public, x_spki).has_value());
    auto const x_decoded_public = x25519::decode_spki(x_spki);
    BOOST_TEST(x_decoded_public.has_value() && *x_decoded_public == x_public);
    std::array<std::uint8_t, x25519::max_pkcs8_size> x_pkcs8{};
    BOOST_TEST(x25519::encode_pkcs8(secret_key, x_pkcs8).has_value());
    auto const x_decoded = x25519::decode_pkcs8(x_pkcs8);
    BOOST_TEST(x_decoded.has_value() && std::ranges::equal(x_decoded->bytes(), secret_key));
}

void round_trips() {
    for (int round = 0; round < 64; ++round) {
        ed25519_round_trip();
        x25519_round_trip();
    }
}

void malformed_der() {
    std::array<std::uint8_t, 32> key{};
    key.fill(0x42);
    std::array<std::uint8_t, 44> ed_spki{};
    std::array<std::uint8_t, 44> x_spki{};
    std::array<std::uint8_t, 48> x_pkcs8{};
    std::array<std::uint8_t, 48> ed_pkcs8{};
    BOOST_TEST(ed25519::encode_spki(*ed25519::public_key::from_bytes(key), ed_spki).has_value());
    BOOST_TEST(x25519::encode_spki(key, x_spki).has_value());
    BOOST_TEST(x25519::encode_pkcs8(key, x_pkcs8).has_value());
    auto const pair = ed25519::keypair::from_secret(key);
    BOOST_TEST(pair.has_value() && ed25519::encode_pkcs8(*pair, ed_pkcs8).has_value());
    std::vector<std::uint8_t> const ed_spki_bytes = bytes_of(ed_spki);
    std::vector<std::uint8_t> const x_spki_bytes = bytes_of(x_spki);
    std::vector<std::uint8_t> const ed_pkcs8_bytes = bytes_of(ed_pkcs8);
    std::vector<std::uint8_t> const x_pkcs8_bytes = bytes_of(x_pkcs8);
    BOOST_TEST(ed25519::decode_spki(ed_spki_bytes).has_value());
    BOOST_TEST(x25519::decode_spki(x_spki_bytes).has_value());
    BOOST_TEST(ed25519::decode_pkcs8(ed_pkcs8_bytes).has_value());
    BOOST_TEST(x25519::decode_pkcs8(x_pkcs8_bytes).has_value());

    // Each curve's OID under the other.
    x25519_spki_refused(ed_spki_bytes, "Ed25519's OID");
    ed25519_spki_refused(x_spki_bytes, "X25519's OID");
    x25519_pkcs8_refused(ed_pkcs8_bytes, "Ed25519's OID");
    ed25519_pkcs8_refused(x_pkcs8_bytes, "X25519's OID");

    // A trailing byte, and one byte short.
    for (auto const* der : {&ed_spki_bytes, &x_spki_bytes, &ed_pkcs8_bytes, &x_pkcs8_bytes}) {
        auto longer = *der;
        longer.push_back(0);
        auto shorter = *der;
        shorter.pop_back();
        if (der == &ed_spki_bytes) {
            ed25519_spki_refused(longer, "a trailing byte");
            ed25519_spki_refused(shorter, "a byte short");
        } else if (der == &x_spki_bytes) {
            x25519_spki_refused(longer, "a trailing byte");
            x25519_spki_refused(shorter, "a byte short");
        } else if (der == &ed_pkcs8_bytes) {
            ed25519_pkcs8_refused(longer, "a trailing byte");
            ed25519_pkcs8_refused(shorter, "a byte short");
        } else {
            x25519_pkcs8_refused(longer, "a trailing byte");
            x25519_pkcs8_refused(shorter, "a byte short");
        }
    }
    ed25519_spki_refused({}, "nothing");
    ed25519_pkcs8_refused({}, "nothing");

    // The outer SEQUENCE's length in long form (30 81 2a), which BER allows and DER does not.
    auto long_spki = ed_spki_bytes;
    long_spki[1] = 0x81;
    long_spki.insert(long_spki.begin() + 2, 0x2a);
    ed25519_spki_refused(long_spki, "a length in long form");
    auto long_pkcs8 = ed_pkcs8_bytes;
    long_pkcs8[1] = 0x81;
    long_pkcs8.insert(long_pkcs8.begin() + 2, 0x2e);
    ed25519_pkcs8_refused(long_pkcs8, "a length in long form");

    // PKCS#8 version 2 (RFC 5958's OneAsymmetricKey with the public key, [1] IMPLICIT).
    auto version2 = ed_pkcs8_bytes;
    version2[1] = 0x51;
    version2[4] = 0x01;
    std::array<std::uint8_t, 32> public_key{};
    if (pair && pair->public_key()) {
        public_key = pair->public_key()->bytes();
    }
    version2.insert(version2.end(), {0x81, 0x21, 0x00});
    version2.insert(version2.end(), public_key.begin(), public_key.end());
    ed25519_pkcs8_refused(version2, "PKCS#8 version 2 with the public key");
    auto version1_marked_2 = ed_pkcs8_bytes;
    version1_marked_2[4] = 0x01;
    ed25519_pkcs8_refused(version1_marked_2, "PKCS#8 marked version 2 without the public key");

    // Ed448's OID (1.3.101.113) and X448's (1.3.101.111).
    auto ed448 = ed_spki_bytes;
    ed448[8] = 0x71;
    ed25519_spki_refused(ed448, "Ed448's OID");
    auto x448 = x_pkcs8_bytes;
    x448[10] = 0x6f;
    x25519_pkcs8_refused(x448, "X448's OID");

    // Each byte of each prefix changed.
    for (std::size_t at = 0; at < 12; ++at) {
        auto changed = ed_spki_bytes;
        changed[at] ^= 0x01U;
        ed25519_spki_refused(changed, "an SPKI prefix byte changed");
        changed = x_spki_bytes;
        changed[at] ^= 0x01U;
        x25519_spki_refused(changed, "an SPKI prefix byte changed");
    }
    for (std::size_t at = 0; at < 16; ++at) {
        auto changed = ed_pkcs8_bytes;
        changed[at] ^= 0x01U;
        ed25519_pkcs8_refused(changed, "a PKCS#8 prefix byte changed");
        changed = x_pkcs8_bytes;
        changed[at] ^= 0x01U;
        x25519_pkcs8_refused(changed, "a PKCS#8 prefix byte changed");
    }
}

void malformed_pem() {
    // The text accepted, then each change refused.
    BOOST_TEST_EQ(der_of(pem::public_key_label, rfc8410_public).size(), 44U);
    pem_refused(pem::private_key_label, rfc8410_public, "another label than the expected");
    pem_refused("PUBLIC", rfc8410_public, "a label that is the start of the text's");
    pem_refused(pem::public_key_label,
                replaced(rfc8410_public, "END PUBLIC KEY", "END PRIVATE KEY"),
                "an END label other than the BEGIN's");
    pem_refused(pem::private_key_label, rewrapped(rfc8410_private, 63), "a line of 63 characters");
    pem_refused(pem::private_key_label, rewrapped(rfc8410_private_v2, 65),
                "a line of 65 characters");
    pem_refused(pem::private_key_label, rewrapped(rfc8410_private_v2, 76),
                "lines of 76 characters");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "\n", "\r\n"), "carriage returns");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "ZuE=\n", "ZuE=\r\n"),
                "a carriage return on one line");
    pem_refused(pem::public_key_label, rfc8410_public.substr(0, rfc8410_public.size() - 1),
                "no line feed after END");
    pem_refused(pem::public_key_label, std::string(rfc8410_public) + "\n",
                "an empty line after END");
    pem_refused(pem::public_key_label, "\n" + std::string(rfc8410_public),
                "an empty line before BEGIN");
    pem_refused(pem::public_key_label, "text\n" + std::string(rfc8410_public), "text before BEGIN");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "-----\nMCow", "-----\n\nMCow"),
                "an empty line after BEGIN");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "MCow", " MCow"),
                "a space before the base64");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "ZuE=", "ZuF="),
                "base64 whose last character carries bits that are not zero");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "ZuE=", "ZuE"),
                "base64 without its padding");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "MCow", "MC-w"),
                "a character outside base64");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "MCow", "MC=w"),
                "padding inside the base64");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "-----BEGIN", "----BEGIN"),
                "four dashes");
    pem_refused(pem::public_key_label, "", "nothing");
    pem_refused(pem::public_key_label, replaced(rfc8410_public, "ZuE=\n", "ZuE=\n\n"),
                "an empty line before END");
    pem_refused(pem::private_key_label, replaced(rfc8410_private, "VhC\n", "VhC\n\n"),
                "an empty line after a full line, before END");

    // Two armoured bodies spliced: a first line of 64 characters that ends with "==", the
    // base64 of 46 bytes, then another line. Each line is base64 that encodes its bytes again
    // to itself; only padding before the last line makes the text another than armour's.
    std::vector<std::uint8_t> const first(46, 0x5a);
    std::vector<std::uint8_t> const second(10, 0x33);
    std::string const first_text = text_of("X", first);
    std::string const second_text = text_of("X", second);
    std::string const head = "-----BEGIN X-----\n";
    std::string const first_line = first_text.substr(head.size(), 65);
    BOOST_TEST_EQ(first_line.size(), 65U);
    BOOST_TEST(first_line.ends_with("==\n"));
    std::string const spliced = head + first_line + second_text.substr(head.size());
    pem_refused("X", spliced, "padding at the end of a line that is not the last");
}

void outputs_too_small() {
    std::array<std::uint8_t, 32> key{};
    key.fill(7);
    std::array<std::uint8_t, 43> short_out{};
    short_out.fill(untouched);
    auto written = ed25519::encode_spki(*ed25519::public_key::from_bytes(key), short_out);
    BOOST_TEST(!written && written.error() == crypto::error::invalid_input_size);
    written = x25519::encode_spki(key, short_out);
    BOOST_TEST(!written && written.error() == crypto::error::invalid_input_size);
    std::array<std::uint8_t, 47> short_pkcs8{};
    short_pkcs8.fill(untouched);
    written = x25519::encode_pkcs8(key, short_pkcs8);
    BOOST_TEST(!written && written.error() == crypto::error::invalid_input_size);
    auto const pair = ed25519::keypair::from_secret(key);
    BOOST_TEST(pair.has_value());
    if (pair) {
        written = ed25519::encode_pkcs8(*pair, short_pkcs8);
        BOOST_TEST(!written && written.error() == crypto::error::invalid_input_size);
    }
    BOOST_TEST(all_untouched(short_out));
    BOOST_TEST(all_untouched(short_pkcs8));
}

/** Keys of another size, and a moved-from key pair, write nothing. */
void keys_refused() {
    std::array<std::uint8_t, 32> key{};
    key.fill(7);
    // Keys of another size: an Ed25519 key is not made of 31 bytes, so its SPKI is never written.
    std::array<std::uint8_t, 48> out{};
    out.fill(untouched);
    auto const short_key = ed25519::public_key::from_bytes(std::span(key).first(31));
    BOOST_TEST(!short_key && short_key.error() == crypto::error::invalid_public_key);
    auto written = x25519::encode_spki(std::span(key).first(31), out);
    BOOST_TEST(!written && written.error() == crypto::error::invalid_public_key);
    written = x25519::encode_pkcs8(std::span(key).first(31), out);
    BOOST_TEST(!written && written.error() == crypto::error::invalid_key_size);
    BOOST_TEST(all_untouched(out));

    // A moved-from key pair.
    auto moved = ed25519::keypair::from_secret(key);
    if (moved) {
        auto const taken = std::move(*moved);
        static_cast<void>(taken);
        std::array<std::uint8_t, 48> pkcs8{};
        pkcs8.fill(untouched);
        written = ed25519::encode_pkcs8(*moved, pkcs8);  // NOLINT(bugprone-use-after-move)
        BOOST_TEST(!written && written.error() == crypto::error::invalid_state);
        BOOST_TEST(all_untouched(pkcs8));
    }
}

/** PEM one character short to armour, one byte short to unarmour, or under a label PEM cannot
 * carry: nothing written. */
void pem_outputs_refused() {
    auto const spki = der_of(pem::public_key_label, rfc8410_public);
    std::string text(pem::armoured_size(pem::public_key_label.size(), spki.size()) - 1,
                     untouched_char);
    auto const armoured = pem::armour(pem::public_key_label, spki, text);
    BOOST_TEST(!armoured && armoured.error() == crypto::error::invalid_input_size);
    BOOST_TEST(all_untouched(text));
    std::array<std::uint8_t, 43> der{};
    der.fill(untouched);
    auto const unarmoured = pem::unarmour(pem::public_key_label, rfc8410_public, der);
    BOOST_TEST(!unarmoured && unarmoured.error() == crypto::error::invalid_input_size);
    BOOST_TEST(all_untouched(der));

    // A label PEM cannot carry.
    for (std::string_view const label : {
             std::string_view{},
             std::string_view{"A\nB"},
             std::string_view{"-A"},
             std::string_view{"A "},
         }) {
        std::string labelled(pem::armoured_size(label.size(), spki.size()), untouched_char);
        auto const refused = pem::armour(label, spki, labelled);
        BOOST_TEST(!refused && refused.error() == crypto::error::invalid_encoding);
        BOOST_TEST(all_untouched(labelled));
    }
}

/** Every length of DER from 0 to 200 bytes armours to lines of 64 and back. */
void pem_lengths() {
    std::vector<std::uint8_t> der;
    for (std::size_t size = 0; size <= 200; ++size) {
        std::string const text = text_of("X", der);
        std::size_t line_start = text.find('\n') + 1;
        auto const end = text.rfind("-----END X-----\n");
        BOOST_TEST(end != std::string::npos && end + 16 == text.size());
        while (line_start < end) {
            auto const line_end = text.find('\n', line_start);
            auto const width = line_end - line_start;
            BOOST_TEST(width == 64 || (line_end + 1 == end && width > 0 && width < 64));
            line_start = line_end + 1;
        }
        BOOST_TEST(der_of("X", text) == der);
        der.push_back(static_cast<std::uint8_t>((size * 37U) + 11U));
    }
}

}  // namespace

int main() {
    rfc8410_keys();
    layouts();
    round_trips();
    malformed_der();
    malformed_pem();
    outputs_too_small();
    keys_refused();
    pem_outputs_refused();
    pem_lengths();
    return test::exit_status(boost::report_errors());
}
