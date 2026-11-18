// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WebCrypto, node's `globalThis.crypto.subtle`, as an outside oracle of Ed25519 and X25519 on
// every backend linked here (libsodium, the default of both on every target), on Emscripten
// under node. From a fixed seed, 200 Ed25519 cases: a key pair made from a random seed, a random
// message (the first one empty) and its signature; WebCrypto imports the seed (PKCS #8) and the
// public key (raw), and the case agrees when WebCrypto's public key and its signature (Ed25519 is
// deterministic) equal ours and it verifies ours. Then 200 X25519 cases: two random secret keys
// and their public keys; WebCrypto imports the first secret key (PKCS #8) and the peer's public
// key (raw), and the case agrees when WebCrypto's public key of the secret key and its derived
// 256 bits equal ours. The program prints `oracle ok <n>`, the cases that agree, and passes when
// n is 400. Each WebCrypto call is an EM_ASYNC_JS function, which suspends the program (the JSPI
// link) and returns its bytes through the heap, as webcpp::hash's webcrypto_oracle_test.cpp.
//
// Built with WEBCPP_TEST_CRYPTO_ORACLE_CORRUPTED, the program flips one bit of the signature of
// Ed25519 case 17, before WebCrypto verifies it, and of our shared secret of X25519 case 42, and
// passes only when exactly those two cases disagree and n is 398: the oracle's teeth.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <emscripten/em_js.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <vector>

namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;

// The cases per algorithm, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t seed = 0x4f7261636c653235ULL;

// Each function returns 0 when every WebCrypto call ran, -1 when one threw (the message goes to
// the console). The inputs are copied before the first await; the heap is written after the
// last. A seed of 32 bytes is a private key in PKCS #8 behind RFC 8410's 16-byte prefix, whose
// OID is 1.3.101.112 for Ed25519 and 1.3.101.110 for X25519; a JWK export of a private key
// carries its public key, `x`, in base64url.
// clang-format off
EM_ASYNC_JS(int, subtle_ed25519, (const std::uint8_t* seed, const std::uint8_t* public_key,
                                  const std::uint8_t* msg, std::size_t msg_size,
                                  const std::uint8_t* sig, std::uint8_t* oracle_public_key,
                                  std::uint8_t* oracle_signature, int* verified), {
    try {
        const pkcs8 = new Uint8Array(48);
        pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
                   0x04, 0x22, 0x04, 0x20]);
        pkcs8.set(HEAPU8.slice(seed, seed + 32), 16);
        const raw = HEAPU8.slice(public_key, public_key + 32);
        const data = HEAPU8.slice(msg, msg + msg_size);
        const signature = HEAPU8.slice(sig, sig + 64);
        const subtle = globalThis.crypto.subtle;
        const private_key = await subtle.importKey("pkcs8", pkcs8, {name: "Ed25519"}, true,
                                                   ["sign"]);
        const jwk = await subtle.exportKey("jwk", private_key);
        const verifier = await subtle.importKey("raw", raw, {name: "Ed25519"}, false,
                                                ["verify"]);
        const ok = await subtle.verify({name: "Ed25519"}, verifier, signature, data);
        const signed = new Uint8Array(await subtle.sign({name: "Ed25519"}, private_key, data));
        const derived = Buffer.from(jwk.x, "base64url");
        if (derived.length !== 32 || signed.length !== 64) {
            console.error("subtle (Ed25519): sizes " + derived.length + ", " + signed.length);
            return -1;
        }
        HEAPU8.set(derived, oracle_public_key);
        HEAPU8.set(signed, oracle_signature);
        HEAP32[verified >> 2] = ok ? 1 : 0;
        return 0;
    } catch (e) {
        console.error("subtle (Ed25519): " + e);
        return -1;
    }
});

EM_ASYNC_JS(int, subtle_x25519, (const std::uint8_t* secret_key, const std::uint8_t* peer,
                                 std::uint8_t* oracle_public_key, std::uint8_t* oracle_shared), {
    try {
        const pkcs8 = new Uint8Array(48);
        pkcs8.set([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                   0x04, 0x22, 0x04, 0x20]);
        pkcs8.set(HEAPU8.slice(secret_key, secret_key + 32), 16);
        const raw = HEAPU8.slice(peer, peer + 32);
        const subtle = globalThis.crypto.subtle;
        const private_key = await subtle.importKey("pkcs8", pkcs8, {name: "X25519"}, true,
                                                   ["deriveBits"]);
        const jwk = await subtle.exportKey("jwk", private_key);
        const public_key = await subtle.importKey("raw", raw, {name: "X25519"}, false, []);
        const shared = new Uint8Array(
            await subtle.deriveBits({name: "X25519", public: public_key}, private_key, 256));
        const derived = Buffer.from(jwk.x, "base64url");
        if (derived.length !== 32 || shared.length !== 32) {
            console.error("subtle (X25519): sizes " + derived.length + ", " + shared.length);
            return -1;
        }
        HEAPU8.set(derived, oracle_public_key);
        HEAPU8.set(shared, oracle_shared);
        return 0;
    } catch (e) {
        console.error("subtle (X25519): " + e);
        return -1;
    }
});

// The versions of the node running this program, and of its OpenSSL, on one line.
EM_JS(void, print_node_versions, (), {
    console.log("oracle run with node " + process.versions.node + ", OpenSSL " +
                process.versions.openssl);
});
// clang-format on

namespace {

using bytes = std::vector<std::uint8_t>;

#ifdef WEBCPP_TEST_CRYPTO_ORACLE_CORRUPTED
constexpr bool corrupted = true;
#else
constexpr bool corrupted = false;
#endif
// The case of each algorithm whose bytes the corrupted program flips.
constexpr std::size_t corrupted_ed25519 = 17;
constexpr std::size_t corrupted_x25519 = 42;

template <std::size_t N>
std::array<std::uint8_t, N> random_array(std::mt19937_64& rng) {
    std::array<std::uint8_t, N> out{};
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(rng() & 0xffU);
    }
    return out;
}

bytes random_bytes(std::mt19937_64& rng, std::size_t min_size, std::size_t max_size) {
    bytes out(std::uniform_int_distribution<std::size_t>(min_size, max_size)(rng));
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(rng() & 0xffU);
    }
    return out;
}

// One Ed25519 case: true when WebCrypto agrees with it.
bool ed25519_case(std::mt19937_64& rng, std::size_t index) {
    auto const key_seed = random_array<32>(rng);
    // The first message is empty; the others cross SHA-512's block of 128 bytes.
    bytes const message = index == 0 ? bytes{} : random_bytes(rng, 1, 300);
    auto const pair = ed25519::keypair::make(key_seed);
    BOOST_TEST(pair.has_value());
    if (!pair) {
        return false;
    }
    auto const public_key = pair->public_key();
    auto signature = pair->sign(message);
    BOOST_TEST(public_key.has_value());
    BOOST_TEST(signature.has_value());
    if (!public_key || !signature) {
        return false;
    }
    BOOST_TEST(ed25519::verify(*public_key, message, *signature).has_value());
    if (corrupted && index == corrupted_ed25519) {
        (*signature)[5] ^= 0x01U;
    }
    std::array<std::uint8_t, 32> oracle_public_key{};
    std::array<std::uint8_t, 64> oracle_signature{};
    int verified = 0;
    int const ran = subtle_ed25519(key_seed.data(), public_key->data(), message.data(),
                                   message.size(), signature->data(), oracle_public_key.data(),
                                   oracle_signature.data(), &verified);
    BOOST_TEST_EQ(ran, 0);
    bool const agrees = ran == 0 && verified == 1 && oracle_public_key == *public_key &&
                        oracle_signature == *signature;
    if (!agrees) {
        std::printf(
            "Ed25519 case %zu: WebCrypto disagrees (verified %d, public key %s, "
            "signature %s)\n",
            index, verified, oracle_public_key == *public_key ? "equal" : "differs",
            oracle_signature == *signature ? "equal" : "differs");
    }
    return agrees;
}

// One X25519 case: true when WebCrypto agrees with it.
bool x25519_case(std::mt19937_64& rng, std::size_t index) {
    auto const secret_key = random_array<32>(rng);
    auto const peer_secret_key = random_array<32>(rng);
    auto const public_key = x25519::public_key(secret_key);
    auto const peer_public_key = x25519::public_key(peer_secret_key);
    BOOST_TEST(public_key.has_value());
    BOOST_TEST(peer_public_key.has_value());
    if (!public_key || !peer_public_key) {
        return false;
    }
    auto const shared = x25519::agree(secret_key, *peer_public_key);
    auto const peer_shared = x25519::agree(peer_secret_key, *public_key);
    BOOST_TEST(shared.has_value());
    BOOST_TEST(peer_shared.has_value());
    if (!shared || !peer_shared) {
        return false;
    }
    auto const ours = shared->bytes();
    auto const theirs = peer_shared->bytes();
    BOOST_TEST(bytes(ours.begin(), ours.end()) == bytes(theirs.begin(), theirs.end()));
    bytes expected(ours.begin(), ours.end());
    if (corrupted && index == corrupted_x25519) {
        expected[7] ^= 0x01U;
    }
    std::array<std::uint8_t, 32> oracle_public_key{};
    std::array<std::uint8_t, 32> oracle_shared{};
    int const ran = subtle_x25519(secret_key.data(), peer_public_key->data(),
                                  oracle_public_key.data(), oracle_shared.data());
    BOOST_TEST_EQ(ran, 0);
    bool const agrees = ran == 0 && oracle_public_key == *public_key &&
                        bytes(oracle_shared.begin(), oracle_shared.end()) == expected;
    if (!agrees) {
        std::printf(
            "X25519 case %zu: WebCrypto disagrees (public key %s, shared secret %s)\n", index,
            oracle_public_key == *public_key ? "equal" : "differs",
            bytes(oracle_shared.begin(), oracle_shared.end()) == expected ? "equal" : "differs");
    }
    return agrees;
}

}  // namespace

int main() {
    std::printf("oracle 25519: seed %llu\n", static_cast<unsigned long long>(seed));
    print_node_versions();
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 rng(seed);
    std::size_t agreed = 0;
    std::vector<std::size_t> ed25519_disagreed;
    std::vector<std::size_t> x25519_disagreed;
    for (std::size_t i = 0; i < cases; ++i) {
        if (ed25519_case(rng, i)) {
            ++agreed;
        } else {
            ed25519_disagreed.push_back(i);
        }
    }
    for (std::size_t i = 0; i < cases; ++i) {
        if (x25519_case(rng, i)) {
            ++agreed;
        } else {
            x25519_disagreed.push_back(i);
        }
    }
    std::printf("oracle ok %zu\n", agreed);
    if (corrupted) {
        BOOST_TEST_EQ(agreed, (2 * cases) - 2);
        BOOST_TEST(ed25519_disagreed == std::vector<std::size_t>{corrupted_ed25519});
        BOOST_TEST(x25519_disagreed == std::vector<std::size_t>{corrupted_x25519});
    } else {
        BOOST_TEST_EQ(agreed, 2 * cases);
    }
    return webcpp::test::exit_status(boost::report_errors());
}
