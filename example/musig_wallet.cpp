// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A wallet split across two devices, a phone and a laptop, whose coins move only when both
// sign (BIP 327's MuSig2): the two public keys are sorted and aggregated into one; each device
// makes a nonce and sends its public half; each signs its part once every public nonce is in;
// the parts add up to one BIP 340 signature under the one x-only key, which on the chain looks
// like any single signer's. The devices' secrets are fixed here, so that the program runs the
// same each time; a real wallet draws them from crypto's random device. The nonces are fresh
// in every run, drawn inside nonce_gen; nothing random is printed.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <utility>

namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace musig = webcpp::crypto::curves::secp256k1::musig;

namespace {

std::array<std::uint8_t, 32> repeated(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(value);
    return bytes;
}

}  // namespace

int main() {
    // Each device's key pair; each sends the other its public key.
    auto const phone = secp256k1::keypair::make(repeated(0x11));
    auto const laptop = secp256k1::keypair::make(repeated(0x22));
    if (!phone || !laptop) {
        return 1;
    }
    auto const phone_key = secp256k1::parse_public_key(*phone->public_key());
    auto const laptop_key = secp256k1::parse_public_key(*laptop->public_key());
    if (!phone_key || !laptop_key) {
        return 1;
    }

    // Both sort the keys (BIP 327's KeySort) and aggregate them: the same key on both devices.
    // The workspace holds libsecp256k1's array of pointers; nothing is allocated.
    std::array<secp256k1::public_key, 2> keys{*phone_key, *laptop_key};
    std::ranges::sort(keys);
    alignas(std::max_align_t) std::array<std::byte, musig::workspace_size(2)> space{};
    auto const wallet_key = musig::key_aggregate(keys, space);
    if (!wallet_key) {
        return 1;
    }
    std::printf("aggregate key made from %zu signers\n", keys.size());

    // The spend both approve: the transaction's 32-byte hash, as a domain library computes it.
    auto const message = repeated(0x5a);

    // Round one: each device makes a nonce for this signature and sends its public half.
    auto phone_nonce = musig::nonce_gen(*phone, *wallet_key, message);
    auto laptop_nonce = musig::nonce_gen(*laptop, *wallet_key, message);
    if (!phone_nonce || !laptop_nonce) {
        return 1;
    }

    // Once both public nonces are in, each device computes the same session.
    std::array<musig::public_nonce, 2> const nonces{phone_nonce->public_part,
                                                    laptop_nonce->public_part};
    auto const nonce_sum = musig::nonce_aggregate(nonces, space);
    if (!nonce_sum) {
        return 1;
    }
    auto const signing_session = musig::nonce_process(*nonce_sum, message, *wallet_key);
    if (!signing_session) {
        return 1;
    }

    // Round two: each signs its part, which consumes its secret nonce; the other checks it.
    auto const phone_part = musig::partial_sign(*phone, std::move(phone_nonce->secret_part),
                                                *wallet_key, *signing_session);
    auto const laptop_part = musig::partial_sign(*laptop, std::move(laptop_nonce->secret_part),
                                                 *wallet_key, *signing_session);
    if (!phone_part || !laptop_part ||
        !musig::partial_signature_verify(*phone_part, nonces[0], *phone_key, *wallet_key,
                                         *signing_session) ||
        !musig::partial_signature_verify(*laptop_part, nonces[1], *laptop_key, *wallet_key,
                                         *signing_session)) {
        return 1;
    }
    std::printf("both partial signatures verify\n");

    // The parts add up to one BIP 340 signature under the wallet's one x-only key.
    std::array<musig::partial_signature, 2> const parts{*phone_part, *laptop_part};
    auto const signature = musig::partial_signature_aggregate(*signing_session, parts, space);
    if (!signature ||
        !secp256k1::verify_schnorr(*signature, message, wallet_key->xonly_public_key())) {
        return 1;
    }
    std::printf("the aggregate signature verifies as one BIP 340 signature\n");
    return 0;
}

// end::program[]
