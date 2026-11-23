// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3) on libsecp256k1: agree's time (the case ecdh_x) against
// the key pair's secret key, the two classes differing only in the secret (one fixed key,
// against random ones), the peer's public key the same; natively and under wasmtime, where the
// engine's compiler decides whether libsecp256k1's field arithmetic stays constant time. Each
// measurement's key pair is made before it, unmeasured, as the Ed25519 signing of
// dudect_sodium_test.cpp makes its own. agree is measured once more as the program's A/A
// control (ecdh_x_aa), both classes the fixed key, prepared by the same instructions;
// `--case <name>` measures one case alone.

#include "dudect.hpp"

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>

namespace {

namespace test = webcpp::test;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
using keypair = secp256k1::basic_keypair<webcpp::crypto::backends::secp256k1>;

// A measurement, the key pair's making and the agreement, takes about 42 microseconds natively
// and 220 under wasmtime (Apple M5, 2026-11-18): 500,000 per run. Under wasmtime the two cases
// took 6.6 minutes of CPU and 35 minutes of wall time on a heavily loaded Apple M5 Max
// (2026-11-21), past run.sh's default bound of 600 seconds: the CI gives crypto's constant-time
// lane WEBCPP_WASIP2_TEST_TIMEOUT=1800, and a local wasip2 run of the lane may need the same
// variable.
constexpr std::size_t count = 500'000;

/**
 * Times agree against the key pair's secret key: a fixed one, against random ones, or, with
 * `Control`, the fixed one for both classes; the case's lines are recorded.
 * @param results Where the case is recorded.
 * @param name The case's name.
 * @param label Its name in the human line.
 * @param peer_key The peer's public key.
 */
template <bool Control, class PublicKey>
void measure_agree(test::case_results& results, char const* name, char const* label,
                   PublicKey const& peer_key) {
    std::array<std::uint8_t, 32> fixed{};
    fixed.fill(0x42);
    std::array<std::uint8_t, 32> secret_key{};
    std::optional<keypair> pair;
    auto const agree_t = test::twice(
        count,
        [&](int which, auto& generator) {
            test::choose<Control>(which, generator, fixed, secret_key);
            // A random secret key is refused only with probability about 2^-128.
            auto made = keypair::from_secret(secret_key);
            if (!made) {
                made = keypair::from_secret(fixed);
            }
            pair.emplace(std::move(*made));
        },
        [&] { static_cast<void>(pair->agree(peer_key)); });
    results.record(name, label, agree_t, true,
                   {{"secret_key", secret_key.data()}, {"object", &*pair}});
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
    auto const selection = test::select_case(argc, argv, {"ecdh_x", "ecdh_x_aa"});
    if (!selection) {
        return 2;
    }
    if (!test::report_data_independent_timing()) {
        return 1;
    }
    test::report_machine();
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = keypair::from_secret(peer_secret);
    if (!peer) {
        std::printf("the peer's key pair was refused\n");
        return 1;
    }
    auto const peer_key = peer->public_key();
    if (!peer_key) {
        std::printf("the peer's public key was refused\n");
        return 1;
    }
    test::case_results results;
    if (selection->runs("ecdh_x")) {
        measure_agree<false>(results, "ecdh_x", "secp256k1 agree", *peer_key);
    }
    if (selection->runs("ecdh_x_aa")) {
        measure_agree<true>(results, "ecdh_x_aa", "secp256k1 agree A/A", *peer_key);
    }
    results.print();
    return test::verdict(results.passes());
}
