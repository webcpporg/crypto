// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still makes MuSig2's nonce through musig::nonce_gen sees (design D12, owner
// decision 14): the call stops the build, with that error alone, although musig.hpp is included.
// The function is compiled, never run.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>

#include <array>
#include <cstdint>

namespace {

namespace secp = webcpp::crypto::curves::secp256k1;
namespace musig = webcpp::crypto::curves::secp256k1::musig;

/** Makes a nonce through the removed name. */
bool nonce_made(secp::keypair const& signer_pair, musig::aggregate_key const& signers_key) {
    std::array<std::uint8_t, 32> const message{};
    // clang-format off
    // expected-error@+2 {{no member named 'nonce_gen' in namespace 'webcpp::crypto::curves::secp256k1::musig'}}
    // clang-format on
    return musig::nonce_gen(signer_pair, signers_key, message).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&nonce_made);
    return 0;
}
