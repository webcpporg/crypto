// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3) on libsodium: X25519's agreement's time against its
// secret key, and Ed25519's signing's against its seed, each pair of classes differing only in
// the secret (all zero, against random ones); natively and under wasmtime, where the engine's
// compiler decides whether libsodium's field arithmetic stays constant time. On wasip2 the
// agreement's |t| is printed and not judged, an open finding whose cause is the host's DIT,
// which wasmtime does not set (see the end of main). The agreement is measured once more as the
// program's A/A control (x25519_agree_aa), both classes the all-zero secret key, prepared by the
// same instructions; `--case <name>` measures one case alone. The planted build
// (dudect_planted_test.cpp) has the agreement alone, and no control.

#include "dudect.hpp"

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>

namespace {

namespace test = webcpp::test;
namespace crypto = webcpp::crypto;
namespace x25519 = crypto::curves::x25519;
using crypto::backends::sodium;

// An agreement and a signature take 15 to 50 microseconds, natively and under wasmtime (Apple
// M5, 2026-11-18), hundreds of times an AES block: half of the 2,000,000 measurements of
// dudect_test.cpp. Under wasmtime the three cases took 4 minutes of CPU and 21 minutes of wall
// time on a heavily loaded Apple M5 Max (2026-11-21), past run.sh's default bound of 600
// seconds: the CI gives crypto's constant-time lane WEBCPP_WASIP2_TEST_TIMEOUT=1800, and a local
// wasip2 run of the lane may need the same variable.
constexpr std::size_t count = 1'000'000;

/**
 * Times X25519's agreement against its secret key: all zero, against random ones, or, with
 * `Control`, all zero for both classes; twice when judged, once when not (`measure_case`).
 * @param judged_case Whether its |t| counts in the verdict.
 * @param secret_key Where each measurement's secret key is written.
 * @param peer The peer's public key.
 * @return The statistic.
 */
template <bool Control>
test::t_statistic measure_agree(bool judged_case, std::array<std::uint8_t, 32>& secret_key,
                                std::array<std::uint8_t, 32> const& peer) {
    std::array<std::uint8_t, 32> const zero{};
    return test::measure_case(
        judged_case, count,
        [&](int which, auto& generator) {
            test::choose<Control>(which, generator, zero, secret_key);
        },
        [&] {
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
            // The planted leak: four early-exit scans of the secret key, 128 reads for the
            // all-zero key and about four for a random one, some tens of nanoseconds. They run
            // inside the library's own guard, as a public operation's code would, so that DIT is
            // set over them where the CPU has it and the lane shows it does not hide a leak of
            // that size; the agreement's own guard then finds DIT set and leaves it so.
            webcpp::crypto::detail::timing_guard const timing;
            for (int scan = 0; scan < 4; ++scan) {
                for (auto const& byte : secret_key) {
                    if (*static_cast<std::uint8_t const volatile*>(&byte) != 0) {
                        break;
                    }
                }
            }
#endif
            static_cast<void>(x25519::agree<sodium>(secret_key, peer));
        });
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    auto const selection = test::select_case(argc, argv, {"x25519_agree"});
#else
    auto const selection =
        test::select_case(argc, argv, {"x25519_agree", "ed25519_sign", "x25519_agree_aa"});
#endif
    if (!selection) {
        return 2;
    }
    if (!test::report_data_independent_timing()) {
        return 1;
    }
    test::report_machine();
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = *x25519::public_key<sodium>(peer_secret);

#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    // The planted build measures only the agreement: it passes only when dudect finds the planted
    // leak there.
    auto const agree_t = measure_agree<false>(true, secret_key, peer);
    test::report_case("x25519_agree", agree_t, true,
                      {{"secret_key", secret_key.data()}, {"peer", peer.data()}});
    std::printf("|t| X25519 agreement %.2f (threshold 10)\n", test::printed(agree_t.t));
    bool const found = test::printed(agree_t.t) >= 10;
    std::printf("planted leak %s\n", found ? "found" : "not found");
    return found ? 0 : 1;
#else
#ifdef __wasip2__
    // X25519's agreement under wasmtime is an open finding, measured and printed but left out of
    // the verdict on wasip2, the one WebAssembly target the lane runs: its |t| and the
    // investigation are in doc/tables/crypto.json (the X25519 family's constant_time on wasip2),
    // which the documentation's constant-time section renders. Its cause is measured: Apple
    // silicon's DIT, which wasmtime does not set and which the WebAssembly cannot set (with DIT
    // set in wasmtime's main thread, an experiment, |t| 1.5 to 2.1). Another WASI target is judged,
    // so that a run of the lane there shows its own value as a failure rather than skip it. Its
    // A/A control, both classes the same key, is judged here as everywhere. Unjudged, the
    // agreement is measured once (measure_case): a second run would change no verdict.
    bool const agree_judged = false;
    char const* const agree_note = " (wasip2: printed, not judged; an open finding)";
#else
    bool const agree_judged = true;
    char const* const agree_note = "";
#endif
    test::case_results results;
    if (selection->runs("x25519_agree")) {
        results.record("x25519_agree", "X25519 agreement",
                       measure_agree<false>(agree_judged, secret_key, peer), agree_judged,
                       {{"secret_key", secret_key.data()}, {"peer", peer.data()}}, agree_note);
    }

    if (selection->runs("ed25519_sign")) {
        using keypair = crypto::curves::ed25519::basic_keypair<sodium>;
        std::array<std::uint8_t, 32> const zero{};
        std::array<std::uint8_t, 64> const message{};
        std::optional<keypair> pair;
        auto const sign_t = test::twice(
            count,
            [&](int which, auto& generator) {
                test::choose(which, generator, zero, secret_key);
                pair.emplace(*keypair::from_secret(secret_key));
            },
            [&] { static_cast<void>(pair->sign(crypto::eddsa, message)); });
        results.record(
            "ed25519_sign", "Ed25519 signing", sign_t, true,
            {{"secret_key", secret_key.data()}, {"message", message.data()}, {"object", &*pair}});
    }

    if (selection->runs("x25519_agree_aa")) {
        results.record("x25519_agree_aa", "X25519 agreement A/A",
                       measure_agree<true>(true, secret_key, peer), true,
                       {{"secret_key", secret_key.data()}, {"peer", peer.data()}});
    }

    results.print();
    return test::verdict(results.passes());
#endif
}
