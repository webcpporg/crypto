// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// dudect's statistics (spec section 8.3): BearSSL's AES-GCM and ChaCha20-Poly1305 seal's time
// against its key, open's against its tag (the failure's zeroing included), ctaes's block
// encryption's against its key, equal's against its second argument, and P-256's ECDSA signing
// and ECDH's x against the key pair's scalar (one fixed scalar, against random ones; the digest
// and the peer's public key fixed), each key pair made before its measurement, unmeasured;
// natively and under wasmtime, where the engine's compiler decides whether BearSSL's 64-bit
// multiplication stays constant time. ChaCha20-Poly1305's open is measured once more as the
// program's A/A control (chacha_open_aa), both classes the same nearly right tag, prepared by
// the same instructions. `--case <name>` measures one case alone.

#include "dudect.hpp"

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/signing.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <utility>

namespace {

namespace test = webcpp::test;

constexpr std::size_t count = 2'000'000;

/**
 * Times an AEAD's seal, whose two classes differ only in the key (all zero, against random keys),
 * and its open, whose two classes both fail (the right tag with its last byte flipped, against
 * random wrong tags), the classic probe of an early exit; a success and a failure differ by
 * design (the failure zeroes data and returns another way), and that difference is public. With
 * `control`, the open is measured once more with both classes the nearly right tag, the A/A
 * control.
 * @param results Where each case measured is recorded.
 * @param selection The cases to measure.
 * @param seal_name The seal's case.
 * @param seal_label Its name in the human line.
 * @param open_name The open's case.
 * @param open_label Its name in the human line.
 * @param control The A/A control's case, or nullptr for none.
 * @param control_label Its name in the human line.
 */
template <class Aead>
void measure_aead(test::case_results& results, test::case_selection const& selection,
                  char const* seal_name, char const* seal_label, char const* open_name,
                  char const* open_label, char const* control, char const* control_label) {
    std::array<std::uint8_t, 32> const zero_key{};
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    std::optional<Aead> made;

    if (selection.runs(seal_name)) {
        auto const seal = test::twice(
            count,
            [&](int which, auto& generator) {
                test::choose(which, generator, zero_key, key);
                made.emplace(*Aead::make(key));
            },
            [&] { static_cast<void>(made->seal(iv, {}, data)); });
        results.record(seal_name, seal_label, seal, true,
                       {{"data", data.data()}, {"key", key.data()}, {"object", &*made}});
    }

    bool const open = selection.runs(open_name);
    bool const open_control = control != nullptr && selection.runs(control);
    if (!open && !open_control) {
        return;
    }
    key.fill(0x42);
    made.emplace(*Aead::make(key));
    std::array<std::uint8_t, 64> const plaintext{};
    std::array<std::uint8_t, 64> ciphertext = plaintext;
    auto const right = *made->seal(iv, {}, ciphertext);
    std::array<std::uint8_t, 16> nearly_right{};
    std::copy(right.data(), right.data() + right.size(), nearly_right.begin());
    nearly_right[15] ^= 1U;
    std::array<std::uint8_t, 16> tag{};
    auto const measure_open = [&]<bool Control> {
        return test::twice(
            count,
            [&](int which, auto& generator) {
                data = ciphertext;
                test::choose<Control>(which, generator, nearly_right, tag);
                if (std::equal(tag.begin(), tag.end(), right.data())) {
                    tag[15] ^= 1U;  // a random tag equal to the right one, which never happens
                }
            },
            [&] { static_cast<void>(made->open(iv, {}, data, tag)); });
    };
    if (open) {
        results.record(open_name, open_label, measure_open.template operator()<false>(), true,
                       {{"data", data.data()}, {"tag", tag.data()}, {"object", &*made}});
    }
    if (open_control) {
        results.record(control, control_label, measure_open.template operator()<true>(), true,
                       {{"data", data.data()}, {"tag", tag.data()}, {"object", &*made}});
    }
}

/**
 * Times P-256's ECDSA signing of a fixed digest (case p256_sign) and its ECDH's x with a fixed
 * peer (case p256_ecdh_x), the two classes differing only in the key pair's scalar: a fixed one,
 * against random ones, each key pair made before its measurement, unmeasured.
 * @param results Where each case measured is recorded.
 * @param selection The cases to measure.
 * @return false when the peer's key pair was refused, which fails the program.
 */
bool measure_p256(test::case_results& results, test::case_selection const& selection) {
    bool const sign = selection.runs("p256_sign");
    bool const ecdh_x = selection.runs("p256_ecdh_x");
    if (!sign && !ecdh_x) {
        return true;
    }
    using keypair = webcpp::crypto::curves::p256::basic_keypair<webcpp::crypto::backends::bearssl>;
    // Signing takes about 190 microseconds and the ECDH 145 natively (a release build on an Apple
    // M5 Max under load, 2026-11-21); with 100,000 measurements of each, the whole program ran in
    // about three minutes natively and two under wasmtime, well within wasmtime's 600 seconds.
    constexpr std::size_t p256_count = 100'000;
    std::array<std::uint8_t, 32> fixed{};
    fixed.fill(0x42);
    std::array<std::uint8_t, 32> scalar{};
    std::array<std::uint8_t, 32> digest{};
    digest.fill(0x17);
    std::array<std::uint8_t, 32> peer_scalar{};
    peer_scalar.fill(0x24);
    auto const peer = keypair::make(peer_scalar);
    auto const peer_key = peer ? peer->public_key() : peer.error();
    if (!peer_key) {
        std::printf("the peer's key pair was refused\n");
        return false;
    }
    std::optional<keypair> pair;
    auto const prepare = [&](int which, auto& generator) {
        test::choose(which, generator, fixed, scalar);
        // A random scalar is 0 or not below n only with probability about 2^-32.
        auto made = keypair::make(scalar);
        if (!made) {
            made = keypair::make(fixed);
        }
        pair.emplace(std::move(*made));
    };
    if (sign) {
        auto const sign_t = test::twice(p256_count, prepare, [&] {
            static_cast<void>(
                pair->sign(webcpp::crypto::ecdsa_sha256, webcpp::crypto::prehashed{digest}));
        });
        results.record("p256_sign", "p256 sign", sign_t, true,
                       {{"digest", digest.data()}, {"scalar", scalar.data()}, {"object", &*pair}});
    }
    if (ecdh_x) {
        auto const ecdh_t =
            test::twice(p256_count, prepare, [&] { static_cast<void>(pair->ecdh_x(*peer_key)); });
        results.record("p256_ecdh_x", "p256 ecdh_x", ecdh_t, true,
                       {{"peer", &*peer_key}, {"scalar", scalar.data()}, {"object", &*pair}});
    }
    return true;
}

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main(int argc, char** argv) {
    auto const selection = test::select_case(argc, argv,
                                             {
                                                 "gcm_seal",
                                                 "gcm_open",
                                                 "chacha_seal",
                                                 "chacha_open",
                                                 "ctaes_encrypt",
                                                 "equal",
                                                 "chacha_open_aa",
                                                 "p256_sign",
                                                 "p256_ecdh_x",
                                             });
    if (!selection) {
        return 2;
    }
    if (!test::report_data_independent_timing()) {
        return 1;
    }
    test::report_machine();
    namespace crypto = webcpp::crypto;
    using block_cipher = crypto::ciphers::aes256<crypto::backends::ctaes>;
    test::case_results results;
    measure_aead<crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>>(
        results, *selection, "gcm_seal", "seal", "gcm_open", "open", nullptr, nullptr);
    measure_aead<crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>>(
        results, *selection, "chacha_seal", "chacha seal", "chacha_open", "chacha open",
        "chacha_open_aa", "chacha open A/A");

    if (selection->runs("ctaes_encrypt")) {
        std::array<std::uint8_t, 32> const zero_key{};
        std::array<std::uint8_t, 32> key{};
        std::optional<block_cipher> block_made;
        std::array<std::uint8_t, 16> block{};
        auto const block_t = test::twice(
            count,
            [&](int which, auto& generator) {
                test::choose(which, generator, zero_key, key);
                block_made.emplace(*block_cipher::make(key));
                block.fill(0);
            },
            [&] { static_cast<void>(block_made->encrypt(block)); });
        results.record("ctaes_encrypt", "ctaes", block_t, true,
                       {{"block", block.data()}, {"key", key.data()}, {"object", &*block_made}});
    }

    if (selection->runs("equal")) {
        std::array<std::uint8_t, 16> const a{};
        std::array<std::uint8_t, 16> b{};
        bool volatile sink = false;  // keeps the comparison from being optimised away
        // The classes differ only in the second argument: equal to the first, against random.
        auto const equal_t = test::twice(
            count, [&](int which, auto& generator) { test::choose(which, generator, a, b); },
            [&] { sink = crypto::equal(a, b); });
        results.record("equal", "equal", equal_t, true, {{"a", a.data()}, {"b", b.data()}});
    }

    if (!measure_p256(results, *selection)) {
        return 1;
    }

    results.print();
    return test::verdict(results.passes());
}
