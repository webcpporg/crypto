// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3) on libsecp256k1: ecdh_x's time against the key pair's
// secret key, the two classes differing only in the secret (one fixed key, against random
// ones), the peer's public key the same; natively and under wasmtime, where the engine's
// compiler decides whether libsecp256k1's field arithmetic stays constant time. Each
// measurement's key pair is made before it, unmeasured, as the Ed25519 signing of
// dudect_sodium_test.cpp makes its own.

#include "dudect.hpp"

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>

int main() {
    if (!webcpp::test::report_data_independent_timing()) {
        return 1;
    }
    namespace secp256k1 = webcpp::crypto::curves::secp256k1;
    using keypair = secp256k1::basic_keypair<webcpp::crypto::backends::secp256k1>;
    // A measurement, the key pair's making and the agreement, takes about 42 microseconds
    // natively and 220 under wasmtime (Apple M5, 2026-11-18): 500,000 measurements keep both runs
    // within wasmtime's 600 seconds.
    constexpr std::size_t count = 500'000;
    std::array<std::uint8_t, 32> fixed{};
    fixed.fill(0x42);
    std::array<std::uint8_t, 32> secret_key{};

    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = keypair::make(peer_secret);
    if (!peer) {
        std::printf("the peer's key pair was refused\n");
        return 1;
    }
    auto const peer_key = peer->public_key();
    if (!peer_key) {
        std::printf("the peer's public key was refused\n");
        return 1;
    }
    std::optional<keypair> pair;
    double const agree_t = webcpp::test::twice(
        count,
        [&](int which, auto& generator) {
            webcpp::test::choose(which, generator, fixed, secret_key);
            // A random secret key is refused only with probability about 2^-128.
            auto made = keypair::make(secret_key);
            if (!made) {
                made = keypair::make(fixed);
            }
            pair.emplace(std::move(*made));
        },
        [&] { static_cast<void>(pair->ecdh_x(*peer_key)); });

    std::printf("|t| secp256k1 ecdh_x %.2f (threshold 10)\n", agree_t);
    return webcpp::test::verdict(agree_t < 10);
}
