// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two P-256 key pairs, made from fixed scalars, agree on the shared point's raw x coordinate with
// agree, the 256 bits WebCrypto's deriveBits gives with ECDH on P-256; then HKDF-SHA-256 of that
// x, with webcpp::hash, derives the 32-byte key a protocol would encrypt with. The x coordinate is
// not a key: the derivation, its salt and its info are the protocol's.
//
// Cross-checked by hand once with OpenSSL 4.1.0 (2026-11-21), each scalar s (32 bytes of 11, then
// of 22) written as SEC 1's ECPrivateKey on prime256v1:
//   echo 30310201010420${s}a00a06082a8648ce3d030107 | xxd -r -p > alice.der
//   openssl ec -inform DER -in alice.der -out alice.pem         (likewise bob)
//   openssl pkey -in bob.pem -pubout -out bob_public.pem
//   openssl pkeyutl -derive -inkey alice.pem -peerkey bob_public.pem | xxd -p -c 64
//   openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:<x>
//     -kdfopt salt:"example salt" -kdfopt info:"example chat v1 key" HKDF   (one line)
// which print the x and the key of p256_ecdh.expected.
// tag::program[]
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/secret.hpp>

#include <webcpp/hash/hkdf.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;

namespace {

// Prints bytes in hex after a name.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (std::uint8_t const octet : bytes) {
        std::printf("%02x", static_cast<unsigned>(octet));
    }
    std::printf("\n");
}

// A text's bytes.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// A key pair whose scalar is one byte repeated: a fixed value, so that the output is fixed. A real
// program draws its key pair with keypair::generate().
boost::system::result<p256::keypair> from_byte(std::uint8_t fill) {
    std::array<std::uint8_t, p256::secret_key_size> scalar{};
    scalar.fill(fill);
    return p256::keypair::from_secret(scalar);
}

}  // namespace

int main() {
    auto const alice = from_byte(0x11);
    auto const bob = from_byte(0x22);
    if (!alice || !bob) {
        std::printf("failed\n");
        return 1;
    }
    // Each side sends its public key, the 65 bytes of WebCrypto's exportKey("raw"), and makes the
    // other's into a public_key, which checks the point once.
    auto const alice_public = alice->public_key();
    auto const bob_public = bob->public_key();
    if (!alice_public || !bob_public) {
        std::printf("failed\n");
        return 1;
    }
    // tag::agree[]
    // Each side combines its key pair with the other's public key: the same x, a secret<32>.
    auto const alice_x = alice->agree(*bob_public);
    auto const bob_x = bob->agree(*alice_public);
    // end::agree[]
    if (!alice_x || !bob_x || !crypto::constant_time_equal(alice_x->bytes(), bob_x->bytes())) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("shared x   both sides agree\n");
    // A real program never prints a shared secret; this one does to show the fixed value.
    print("x         ", alice_x->bytes());

    // tag::derive[]
    // The x is hashed into the key: HKDF-SHA-256 (RFC 5869) with the protocol's salt and info.
    crypto::secret<32> key;
    auto const derived = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
        key.writable(), bytes_of("example salt"), alice_x->bytes(),
        bytes_of("example chat v1 key"));
    // end::derive[]
    if (!derived) {
        std::printf("failed\n");
        return 1;
    }
    print("HKDF key  ", key.bytes());
    return 0;
}

// end::program[]
