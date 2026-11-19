// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WebCrypto, node's `globalThis.crypto.subtle`, as an outside oracle of RFC 8410's SPKI and
// PKCS#8 on libsodium (design D30), on Emscripten: for 200 seeded keys per curve, importKey of
// ours with "spki" and "pkcs8" and exportKey again give our bytes, an Ed25519 key signs as ours
// does and an X25519 key agrees as ours does; and for 200 key pairs per curve that WebCrypto
// generates, its "spki" and "pkcs8" decode to a key pair whose public key is the SPKI's and that
// signs as WebCrypto's does (Ed25519) or gives the same public key (X25519), and encode again to
// the same bytes. Each WebCrypto call is an EM_ASYNC_JS function, which suspends the program
// (the JSPI link) and returns its bytes through a heap buffer.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <emscripten/em_js.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <vector>

namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace test = webcpp::test;

// The cases per curve and direction, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t seed = 0x57656243727970ULL;

// Ours through WebCrypto: imports `pkcs8` (48 bytes) and `spki` (44 bytes) of curve 0 (Ed25519)
// or 1 (X25519), exports each again into out[0, 48) and out[48, 92), then writes into out[92, ...)
// the Ed25519 signature of the message (64 bytes), or the X25519 shared secret with the peer's
// SPKI (32 bytes). Returns 0, or -1 when WebCrypto refused (the message goes to the console).
// The inputs are copied before the first await; the heap is read again after the last.
// clang-format off
EM_ASYNC_JS(int, subtle_round_trip, (int curve, const std::uint8_t* pkcs8, const std::uint8_t* spki,
                                     const std::uint8_t* peer_spki, const std::uint8_t* message,
                                     std::size_t message_size, std::uint8_t* out), {
    const name = curve === 0 ? "Ed25519" : "X25519";
    const private_der = HEAPU8.slice(pkcs8, pkcs8 + 48);
    const public_der = HEAPU8.slice(spki, spki + 44);
    const peer_der = HEAPU8.slice(peer_spki, peer_spki + 44);
    const data = HEAPU8.slice(message, message + message_size);
    try {
        const subtle = globalThis.crypto.subtle;
        const private_key = await subtle.importKey(
            "pkcs8", private_der, {name}, true, curve === 0 ? ["sign"] : ["deriveBits"]);
        const public_key = await subtle.importKey(
            "spki", public_der, {name}, true, curve === 0 ? ["verify"] : []);
        const exported_private = new Uint8Array(await subtle.exportKey("pkcs8", private_key));
        const exported_public = new Uint8Array(await subtle.exportKey("spki", public_key));
        let last;
        if (curve === 0) {
            last = new Uint8Array(await subtle.sign({name}, private_key, data));
        } else {
            const peer = await subtle.importKey("spki", peer_der, {name}, true, []);
            last = new Uint8Array(await subtle.deriveBits({name, public: peer}, private_key, 256));
        }
        if (exported_private.length !== 48 || exported_public.length !== 44) {
            console.error("exportKey: sizes " + exported_private.length + ", " +
                          exported_public.length);
            return -1;
        }
        HEAPU8.set(exported_private, out);
        HEAPU8.set(exported_public, out + 48);
        HEAPU8.set(last, out + 92);
        return 0;
    } catch (e) {
        console.error(name + " round trip: " + e);
        return -1;
    }
});

// WebCrypto's own key pair of curve 0 (Ed25519) or 1 (X25519): exportKey with "pkcs8" into
// out[0, 48) and "spki" into out[48, 92), and, for Ed25519, the signature of the message into
// out[92, 156). Returns 0, or -1 when WebCrypto refused or exported another size.
EM_ASYNC_JS(int, subtle_generated, (int curve, const std::uint8_t* message,
                                    std::size_t message_size, std::uint8_t* out), {
    const name = curve === 0 ? "Ed25519" : "X25519";
    const data = HEAPU8.slice(message, message + message_size);
    try {
        const subtle = globalThis.crypto.subtle;
        const pair = await subtle.generateKey(
            {name}, true, curve === 0 ? ["sign", "verify"] : ["deriveBits"]);
        const exported_private = new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
        const exported_public = new Uint8Array(await subtle.exportKey("spki", pair.publicKey));
        if (exported_private.length !== 48 || exported_public.length !== 44) {
            console.error("exportKey: sizes " + exported_private.length + ", " +
                          exported_public.length);
            return -1;
        }
        let signature = new Uint8Array(0);
        if (curve === 0) {
            signature = new Uint8Array(await subtle.sign({name}, pair.privateKey, data));
        }
        HEAPU8.set(exported_private, out);
        HEAPU8.set(exported_public, out + 48);
        HEAPU8.set(signature, out + 92);
        return 0;
    } catch (e) {
        console.error(name + " generated: " + e);
        return -1;
    }
});

// The versions of the node running this program, and of its OpenSSL, on one line.
EM_JS(void, print_node_versions, (), {
    console.log("webcrypto-node run with node " + process.versions.node + ", OpenSSL " +
                process.versions.openssl);
});
// clang-format on

namespace {

/** 32 bytes of the seeded generator. */
std::array<std::uint8_t, 32> drawn(std::mt19937_64& generator) {
    std::array<std::uint8_t, 32> bytes{};
    for (auto& b : bytes) {
        b = static_cast<std::uint8_t>(generator() & 0xffU);
    }
    return bytes;
}

/** The message each Ed25519 key pair signs, "spki pkcs#8". */
constexpr std::array<std::uint8_t, 11> message{
    's', 'p', 'k', 'i', ' ',       // "spki "
    'p', 'k', 'c', 's', '#', '8',  // "pkcs#8"
};

void ed25519_through_webcrypto(std::mt19937_64& generator) {
    for (std::size_t round = 0; round < cases; ++round) {
        auto const seed_bytes = drawn(generator);
        auto const pair = ed25519::keypair::make(seed_bytes);
        if (!BOOST_TEST(pair.has_value())) {
            static_cast<void>(std::fprintf(stderr, "Ed25519 key pair not made: seed %s\n",
                                           test::to_hex(seed_bytes).c_str()));
            continue;
        }
        auto const public_key = pair->public_key();
        auto const signature = pair->sign(message);
        if (!BOOST_TEST(public_key.has_value() && signature.has_value())) {
            static_cast<void>(std::fprintf(stderr, "Ed25519 key pair failed: seed %s\n",
                                           test::to_hex(seed_bytes).c_str()));
            continue;
        }
        std::array<std::uint8_t, 48> pkcs8{};
        std::array<std::uint8_t, 44> spki{};
        BOOST_TEST(ed25519::encode_pkcs8(*pair, pkcs8).has_value());
        BOOST_TEST(ed25519::encode_spki(*public_key, spki).has_value());
        std::array<std::uint8_t, 156> out{};
        BOOST_TEST_EQ(subtle_round_trip(0, pkcs8.data(), spki.data(), spki.data(), message.data(),
                                        message.size(), out.data()),
                      0);
        bool const same =
            BOOST_TEST(std::ranges::equal(std::span(out).first(48), pkcs8)) &&
            BOOST_TEST(std::ranges::equal(std::span(out).subspan(48, 44), spki)) &&
            BOOST_TEST(std::ranges::equal(std::span(out).subspan(92, 64), *signature));
        if (!same) {
            static_cast<void>(std::fprintf(stderr, "Ed25519 disagrees with WebCrypto: seed %s\n",
                                           test::to_hex(seed_bytes).c_str()));
        }
    }
}

void ed25519_from_webcrypto() {
    for (std::size_t round = 0; round < cases; ++round) {
        std::array<std::uint8_t, 156> out{};
        if (!BOOST_TEST_EQ(subtle_generated(0, message.data(), message.size(), out.data()), 0)) {
            continue;
        }
        auto const pkcs8 = std::span(out).first(48);
        auto const spki = std::span(out).subspan(48, 44);
        auto const pair = ed25519::decode_pkcs8(pkcs8);
        auto const public_key = ed25519::decode_spki(spki);
        if (!BOOST_TEST(pair.has_value() && public_key.has_value())) {
            continue;
        }
        auto const its_public = pair->public_key();
        auto const signature = pair->sign(message);
        if (!BOOST_TEST(its_public.has_value() && signature.has_value())) {
            continue;
        }
        BOOST_TEST(*its_public == *public_key);
        BOOST_TEST(std::ranges::equal(*signature, std::span(out).subspan(92, 64)));
        std::array<std::uint8_t, 48> pkcs8_again{};
        std::array<std::uint8_t, 44> spki_again{};
        BOOST_TEST(ed25519::encode_pkcs8(*pair, pkcs8_again).has_value());
        BOOST_TEST(ed25519::encode_spki(*public_key, spki_again).has_value());
        BOOST_TEST(std::ranges::equal(pkcs8_again, pkcs8));
        BOOST_TEST(std::ranges::equal(spki_again, spki));
    }
}

void x25519_through_webcrypto(std::mt19937_64& generator) {
    for (std::size_t round = 0; round < cases; ++round) {
        auto const secret_key = drawn(generator);
        auto const peer_secret = drawn(generator);
        auto const public_key = x25519::public_key(secret_key);
        auto const peer_public = x25519::public_key(peer_secret);
        if (!BOOST_TEST(public_key.has_value() && peer_public.has_value())) {
            continue;
        }
        std::array<std::uint8_t, 48> pkcs8{};
        std::array<std::uint8_t, 44> spki{};
        std::array<std::uint8_t, 44> peer_spki{};
        BOOST_TEST(x25519::encode_pkcs8(secret_key, pkcs8).has_value());
        BOOST_TEST(x25519::encode_spki(*public_key, spki).has_value());
        BOOST_TEST(x25519::encode_spki(*peer_public, peer_spki).has_value());
        std::array<std::uint8_t, 124> out{};
        BOOST_TEST_EQ(subtle_round_trip(1, pkcs8.data(), spki.data(), peer_spki.data(),
                                        message.data(), message.size(), out.data()),
                      0);
        auto const shared = x25519::agree(secret_key, *peer_public);
        bool const same =
            BOOST_TEST(std::ranges::equal(std::span(out).first(48), pkcs8)) &&
            BOOST_TEST(std::ranges::equal(std::span(out).subspan(48, 44), spki)) &&
            BOOST_TEST(shared.has_value() &&
                       std::ranges::equal(std::span(out).subspan(92, 32), shared->bytes()));
        if (!same) {
            static_cast<void>(std::fprintf(stderr,
                                           "X25519 disagrees with WebCrypto: secret key %s\n",
                                           test::to_hex(secret_key).c_str()));
        }
    }
}

void x25519_from_webcrypto() {
    for (std::size_t round = 0; round < cases; ++round) {
        std::array<std::uint8_t, 92> out{};
        if (!BOOST_TEST_EQ(subtle_generated(1, message.data(), message.size(), out.data()), 0)) {
            continue;
        }
        auto const pkcs8 = std::span(out).first(48);
        auto const spki = std::span(out).subspan(48, 44);
        auto const secret_key = x25519::decode_pkcs8(pkcs8);
        auto const public_key = x25519::decode_spki(spki);
        if (!BOOST_TEST(secret_key.has_value() && public_key.has_value())) {
            continue;
        }
        auto const derived = x25519::public_key(secret_key->bytes());
        BOOST_TEST(derived.has_value() && *derived == *public_key);
        std::array<std::uint8_t, 48> pkcs8_again{};
        std::array<std::uint8_t, 44> spki_again{};
        BOOST_TEST(x25519::encode_pkcs8(secret_key->bytes(), pkcs8_again).has_value());
        BOOST_TEST(x25519::encode_spki(*public_key, spki_again).has_value());
        BOOST_TEST(std::ranges::equal(pkcs8_again, pkcs8));
        BOOST_TEST(std::ranges::equal(spki_again, spki));
    }
}

}  // namespace

int main() {
    print_node_versions();
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(seed);
    ed25519_through_webcrypto(generator);
    ed25519_from_webcrypto();
    x25519_through_webcrypto(generator);
    x25519_from_webcrypto();
    std::printf("formats against WebCrypto: %zu cases per curve and direction\n", cases);
    return test::exit_status(boost::report_errors());
}
