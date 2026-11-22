// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs a Bitcoin legacy or segwit v0 input's sighash: SHA-256d of the transaction's
// serialization, computed by the program with webcpp::hash, signed as a digest with ECDSA over
// SHA-256, verified, and written as strict DER for the witness. Crypto computes no sighash: the
// serialization and its hash are the protocol's, a domain library's work; the sighash is the
// SHA-256 of a SHA-256, so the second hash is the scheme's own and the digest is honest under
// crypto::ecdsa_sha256. A taproot sighash, BIP341's tagged hash, is the message of
// crypto::schnorr instead (musig_taproot.cpp, taproot_tweak.cpp).
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

// Prints bytes in hex after a name, 32 bytes (64 digits) to a line, the lines after the first
// indented under the first, so that a long value stays readable on a narrow page.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    int const indent = std::printf("%s ", name);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0 && i % 32 == 0) {
            std::printf("\n%*s", indent, "");
        }
        std::printf("%02x", bytes[i]);
    }
    std::printf("\n");
}

}  // namespace

int main() {
    // A fixed secret keeps the output the same on every run: ECDSA here is deterministic
    // (RFC 6979), so the same key and sighash always give the same signature.
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x11);
    auto key = secp256k1::keypair::make(secret);
    wipe(std::as_writable_bytes(std::span(secret)));
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    if (!public_key) {
        return 1;
    }

    // tag::sighash[]
    // The program's work, not crypto's: the serialization a domain library writes (BIP143's for
    // segwit v0), stood for here by a fixed preimage, and its SHA-256d.
    std::string_view const preimage = "example transaction serialization";
    webcpp::hash::sha2_256 first;
    first.update(preimage.data(), preimage.size());
    auto const once = first.result();
    webcpp::hash::sha2_256 second;
    second.update(once.data(), once.size());
    auto const sighash = second.result();
    print("sighash", std::span<std::uint8_t const>(sighash.data(), sighash.size()));

    // The sighash is a SHA-256 digest: marked as one, ECDSA over SHA-256 signs it as given.
    auto const signature = key->sign(crypto::ecdsa_sha256, crypto::prehashed{sighash});
    if (!signature || !crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{sighash},
                                      *public_key)) {
        return 1;
    }
    std::array<std::uint8_t, secp256k1::max_der_size> der{};
    auto const der_size = secp256k1::to_der(*signature, der);
    if (!der_size) {
        return 1;
    }
    print("der    ", std::span<std::uint8_t const>(der).first(*der_size));
    // end::sighash[]
    std::printf("verified, low S: %s\n", secp256k1::is_low_s(*signature) ? "yes" : "no");
    return 0;
}

// end::program[]
