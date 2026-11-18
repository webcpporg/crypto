// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Reads RFC 8410's Ed25519 private key in PEM (section 10.3), as OpenSSL or WebCrypto export it,
// writes its public key as PEM, which is the RFC's section 10.1 to the character, and signs with
// it; writes an X25519 key pair's public key the same way; and refuses the RFC's version 2 of the
// private key, which carries the public key too. Prints the PEM texts and each verdict.
// tag::program[]
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace pem = webcpp::crypto::pem;

namespace {

// RFC 8410 section 10.3's private key: published, never a real key.
constexpr std::string_view private_pem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    "-----END PRIVATE KEY-----\n";

// The same key pair in RFC 5958's version 2, with an attribute and the public key.
constexpr std::string_view version2_pem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB\n"
    "Z9w7lshQhqowtrbLDFw4rXAxZuE=\n"
    "-----END PRIVATE KEY-----\n";

// Prints a public key's SPKI as PEM.
bool print_public_pem(std::array<std::uint8_t, 44> const& spki) {
    std::array<char, pem::armoured_size(pem::public_key_label.size(), 44)> text{};
    auto const written = pem::armour(pem::public_key_label, spki, text);
    if (!written) {
        return false;
    }
    std::printf("%.*s", static_cast<int>(*written), text.data());
    return true;
}

// An Ed25519 key pair from PEM, its public key back to PEM, and a signature.
bool ed25519_from_pem() {
    // The PKCS#8 holds the seed: a secret<N>, which wipes itself.
    crypto::secret<ed25519::max_pkcs8_size> pkcs8;
    auto const read = pem::unarmour(pem::private_key_label, private_pem, pkcs8.writable());
    if (!read) {
        return false;
    }
    auto const pair = ed25519::decode_pkcs8(pkcs8.bytes());
    if (!pair) {
        return false;
    }
    auto const public_key = pair->public_key();
    std::array<std::uint8_t, ed25519::max_spki_size> spki{};
    if (!public_key || !ed25519::encode_spki(*public_key, spki) || !print_public_pem(spki)) {
        return false;
    }
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const signature = pair->sign(message);
    return signature && ed25519::verify(*public_key, message, *signature);
}

// An X25519 public key of RFC 7748's Alice, as SPKI in PEM.
bool x25519_to_pem() {
    std::array<std::uint8_t, 32> const alice_secret{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
        0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
        0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    auto const public_key = x25519::public_key(alice_secret);
    std::array<std::uint8_t, x25519::max_spki_size> spki{};
    return public_key && x25519::encode_spki(*public_key, spki) && print_public_pem(spki);
}

// Version 2 decodes from PEM, then the PKCS#8 is refused: strict decoding takes one form.
bool version2_refused() {
    crypto::secret<128> der;
    auto const read = pem::unarmour(pem::private_key_label, version2_pem, der.writable());
    if (!read) {
        return false;
    }
    auto const pair = ed25519::decode_pkcs8(der.bytes().first(*read));
    if (!pair && pair.error() == crypto::error::invalid_encoding) {
        std::printf("version 2 refused: invalid_encoding\n");
        return true;
    }
    return false;
}

}  // namespace

int main() {
    if (!ed25519_from_pem() || !x25519_to_pem() || !version2_refused()) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("signed and verified\n");
    return 0;
}

// end::program[]
