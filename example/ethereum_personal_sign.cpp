// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs a message as an Ethereum wallet's personal_sign does, then finds the signer's address
// from the signature alone. The program builds EIP-191's digest itself with webcpp::hash's
// Keccak-256, signs it as crypto::prehashed with crypto::ecdsa_keccak256_recoverable, prints r,
// s and v, recovers the key and prints its address. crypto computes none of the protocol's
// encodings: not the digest (EIP-191's here, EIP-712's or a transaction's elsewhere), not v
// (27 + the recovery id for personal_sign, 35 + 2 x chain_id + the id for EIP-155, the id itself
// as a typed transaction's yParity), not the address. The key and the message are web3.js's
// documented example (web3.eth.accounts.sign('Some data', ...)), whose signature this prints.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/keccak.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// Keccak-256 of bytes, Ethereum's hash (the original padding, not SHA3-256's).
std::array<std::uint8_t, 32> keccak_256(std::span<std::uint8_t const> bytes) {
    webcpp::hash::keccak_256 hasher;
    hasher.update(bytes.data(), bytes.size());
    auto const hash_result = hasher.result();
    std::array<std::uint8_t, 32> digest{};
    std::copy_n(hash_result.data(), digest.size(), digest.begin());
    return digest;
}

// tag::digest[]
// EIP-191's personal_sign digest: Keccak-256 of "\x19Ethereum Signed Message:\n", the message's
// length in decimal, and the message. The protocol's rule, computed here, not by crypto.
std::array<std::uint8_t, 32> personal_sign_digest(std::string_view message) {
    std::string prefixed =
        "\x19"
        "Ethereum Signed Message:\n";
    prefixed += std::to_string(message.size());
    prefixed += message;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return keccak_256({reinterpret_cast<std::uint8_t const*>(prefixed.data()), prefixed.size()});
}

// end::digest[]

void print_hex(char const* label, std::span<std::uint8_t const> bytes) {
    std::printf("%s0x", label);
    for (std::uint8_t const octet : bytes) {
        std::printf("%02x", static_cast<unsigned>(octet));
    }
    std::printf("\n");
}

}  // namespace

int main() {
    // web3.js's documented key; a wallet's own comes from its secret storage.
    constexpr std::array<std::uint8_t, 32> secret{
        0x4c, 0x08, 0x83, 0xa6, 0x91, 0x02, 0x93, 0x7d, 0x62, 0x31, 0x47,
        0x1b, 0x5d, 0xbb, 0x62, 0x04, 0xfe, 0x51, 0x29, 0x61, 0x70, 0x82,
        0x79, 0x2a, 0xe4, 0x68, 0xd0, 0x1a, 0x3f, 0x36, 0x23, 0x18,
    };
    auto const wallet = secp256k1::keypair::from_secret(secret);
    if (!wallet) {
        return 1;
    }

    // tag::sign[]
    // The wallet signs EIP-191's digest as given: crypto::prehashed, never hashed again.
    auto const digest = personal_sign_digest("Some data");
    auto const signature =
        wallet->sign(crypto::ecdsa_keccak256_recoverable, crypto::prehashed{digest});
    if (!signature) {
        return 1;
    }
    std::span<std::uint8_t const, 65> const signed_bytes = signature->bytes();
    print_hex("r: ", signed_bytes.first<32>());
    print_hex("s: ", signed_bytes.subspan<32, 32>());
    // personal_sign's v is 27 + the recovery id; EIP-155's and a typed transaction's differ.
    std::printf("v: %u\n", 27U + signature->recovery_id());
    // end::sign[]

    // tag::recover[]
    // The reader recovers the key from the signature and the same digest, and makes its address:
    // the last 20 bytes of Keccak-256 over the uncompressed key without its 0x04.
    auto const signer = secp256k1::recover(crypto::ecdsa_keccak256_recoverable, *signature,
                                           crypto::prehashed{digest});
    if (!signer) {
        return 1;
    }
    auto const uncompressed = signer->uncompressed();
    auto const key_hash = keccak_256(std::span(uncompressed).subspan<1>());
    print_hex("address: ", std::span(key_hash).last<20>());
    // end::recover[]
    return 0;
}

// end::program[]
