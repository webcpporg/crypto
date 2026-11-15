// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Signs a native P2WPKH input of a Bitcoin transaction: BIP143's published example, its
// second input. The BIP143 sighash is computed with Boost.Hash2's SHA-256, signed with
// secp256k1's ECDSA (RFC 6979, low-S), encoded as strict DER, and checked against the
// sighash and the signature BIP143 publishes; the program prints the input's witness.

#include <webcpp/crypto/secp256k1.hpp>

#include <boost/hash2/sha2.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace secp = webcpp::crypto::secp256k1;

namespace {

using bytes = std::vector<std::uint8_t>;

bytes from_hex(std::string_view hex) {
    auto const digit = [](char c) {
        return static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((digit(hex[2 * i]) << 4U) | digit(hex[(2 * i) + 1]));
    }
    return out;
}

std::string to_hex(std::span<std::uint8_t const> data) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (std::uint8_t const b : data) {
        out += digits[b >> 4U];
        out += digits[b & 0xfU];
    }
    return out;
}

// Bitcoin's hash: SHA-256 twice.
std::array<std::uint8_t, 32> double_sha256(std::span<std::uint8_t const> data) {
    boost::hash2::sha2_256 first;
    first.update(data.data(), data.size());
    auto const once = first.result();
    boost::hash2::sha2_256 second;
    second.update(once.data(), once.size());
    auto const twice = second.result();
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = twice[i];
    }
    return out;
}

void append(bytes& out, std::span<std::uint8_t const> data) {
    out.insert(out.end(), data.begin(), data.end());
}

void append(bytes& out, std::string_view hex) {
    append(out, from_hex(hex));
}

}  // namespace

int main() {
    // BIP143's unsigned transaction: its two outpoints, their sequences and its two outputs.
    bytes prevouts;
    append(prevouts, "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000");
    append(prevouts, "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000");
    bytes const sequences = from_hex("eeffffffffffffff");
    bytes outputs;
    append(outputs, "202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac");
    append(outputs, "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac");

    // The second input's key, whose P2WPKH program is HASH160 of its compressed public key.
    auto const secret =
        from_hex("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
    auto key = secp::keypair::make(secret);
    if (!key) {
        std::cerr << "make: " << key.error().message() << '\n';
        return 1;
    }
    auto const public_key = key->public_key();
    if (!public_key) {
        std::cerr << "public_key: " << public_key.error().message() << '\n';
        return 1;
    }

    // BIP143's preimage for that input with SIGHASH_ALL: the scriptCode of P2WPKH is
    // OP_DUP OP_HASH160 <20-byte key hash> OP_EQUALVERIFY OP_CHECKSIG, and its amount is 6 BTC.
    bytes preimage;
    append(preimage, "01000000");                // nVersion
    append(preimage, double_sha256(prevouts));   // hashPrevouts
    append(preimage, double_sha256(sequences));  // hashSequence
    append(preimage, "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000");
    append(preimage, "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac");  // scriptCode
    append(preimage, "0046c32300000000");                                      // amount
    append(preimage, "ffffffff");                                              // nSequence
    append(preimage, double_sha256(outputs));                                  // hashOutputs
    append(preimage, "11000000");                                              // nLockTime
    append(preimage, "01000000");  // nHashType, SIGHASH_ALL
    auto const sighash = double_sha256(preimage);

    auto const signature = key->sign_ecdsa(sighash);
    if (!signature) {
        std::cerr << "sign_ecdsa: " << signature.error().message() << '\n';
        return 1;
    }
    std::array<std::uint8_t, secp::max_der_size> der{};
    auto const size = secp::to_der(*signature, der);
    if (!size) {
        std::cerr << "to_der: " << size.error().message() << '\n';
        return 1;
    }
    // The witness's signature is the DER encoding followed by the hash type.
    bytes witness_signature(der.begin(), der.begin() + static_cast<std::ptrdiff_t>(*size));
    witness_signature.push_back(0x01);

    // What BIP143 publishes for this input.
    bool const agrees =
        to_hex(sighash) == "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670" &&
        to_hex(*public_key) ==
            "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357" &&
        to_hex(witness_signature) ==
            "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c45"
            "18331561406f90300e8f3358f51928d43c212a8caed02de67eebee01" &&
        secp::verify_ecdsa(*signature, sighash, *public_key).has_value();
    if (!agrees) {
        std::cerr << "the signature differs from BIP143's\n";
        return 1;
    }

    // The witness: two items, the signature and the public key, each after its length.
    bytes witness{0x02, static_cast<std::uint8_t>(witness_signature.size())};
    append(witness, witness_signature);
    witness.push_back(static_cast<std::uint8_t>(public_key->size()));
    append(witness, *public_key);
    std::cout << "sighash " << to_hex(sighash) << '\n';
    std::cout << "witness " << to_hex(witness) << '\n';
}
