// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's recover given an ECDSA signature of 64 bytes, which has no recovery id, stops at
// recover, which names the recoverable signature it takes and how to make one, and with that
// error alone (design R1).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: recover takes a curves::secp256k1::recoverable_signature: make one from 65 bytes with curves::secp256k1::recoverable_signature::from_bytes.}}
// clang-format on
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.back() = 1;
    auto const key = crypto::curves::secp256k1::keypair::from_secret(secret_key);
    if (!key) {
        return 1;
    }
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const signature = key->sign(crypto::ecdsa_sha256, message);
    return signature && crypto::curves::secp256k1::recover(crypto::ecdsa_sha256_recoverable,
                                                           *signature, message)
               ? 0
               : 1;
}
