// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// WebCrypto, node's `globalThis.crypto.subtle`, as an outside oracle of P-256 on BearSSL, on
// Emscripten under node: the algorithms Trystero 0.27.0's peers use, ECDSA P-256 with SHA-256 and
// ECDH P-256. From a printed seed, 200 cases, each with a random scalar, a second random scalar
// (the peer's) and a random message (the first one empty):
//
// - Signatures: WebCrypto imports encode_pkcs8's bytes ("pkcs8", ECDSA P-256, sign) and the
//   public key's uncompressed() ("raw", verify). WebCrypto's ECDSA with SHA-256 hashes the message
//   itself, so ours signs sha256(message). Check one: WebCrypto verifies sign_ecdsa's signature
//   and its normalize_ecdsa form. Check two: WebCrypto signs the message and verify_ecdsa accepts
//   its signature with the SHA-256 this program computes. Whether WebCrypto's S is low is
//   counted and printed, not required: WebCrypto's S is either.
// - ECDH: WebCrypto imports the first scalar's encode_pkcs8 ("pkcs8", ECDH P-256) and the peer's
//   uncompressed point ("raw") and derives 256 bits, which equal ecdh_x. One check.
// - Formats: WebCrypto's exportKey of the keys it imported, "pkcs8" of both private keys, "spki"
//   and "raw" of the ECDSA public key, equal encode_pkcs8's, encode_spki's and uncompressed()'s
//   bytes, byte for byte. One check.
//
// n counts the checks that agree: 2 per signature case, 1 per ECDH case and 1 per formats case,
// 800 in all. The program prints `oracle ok <n>` and passes when n is 800. Each WebCrypto call
// is in an EM_ASYNC_JS function, which suspends the program (the JSPI link) and returns its bytes
// through the heap, as oracle_25519_test.cpp.
//
// Built with WEBCPP_TEST_CRYPTO_ORACLE_CORRUPTED, the program flips one bit of the signature of
// case 17 before WebCrypto verifies it (both its forms, r carrying the bit) and of the shared x of
// case 42, and passes only when exactly those two checks disagree and n is 798: the oracle's
// teeth.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <emscripten/em_js.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <string>
#include <vector>

namespace p256 = webcpp::crypto::curves::p256;
namespace test = webcpp::test;

// The cases, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t seed = 0x503235364e6f6465ULL;

// One case through WebCrypto. In: our PKCS#8 (138 bytes), our point and the peer's (65 bytes
// each), the message, our signature and its normalized form (64 bytes each). Out: WebCrypto's
// signature of the message (64 bytes, r || s), its 256 ECDH bits, its exports: "pkcs8" of the
// ECDSA key and of the ECDH key (138 bytes each), "spki" (91 bytes) and "raw" (65 bytes) of the
// ECDSA public key, whose sizes it writes into `sizes`; and into `verified` 1 when it verifies
// both forms of our signature. Returns 0 when every WebCrypto call ran, -1 when one threw (the
// message goes to the console). The inputs are copied before the first await; the heap is written
// after the last.
// clang-format off
EM_ASYNC_JS(int, subtle_p256, (const std::uint8_t* pkcs8, const std::uint8_t* point,
                               const std::uint8_t* peer_point, const std::uint8_t* msg,
                               std::size_t msg_size, const std::uint8_t* sig,
                               const std::uint8_t* normalized, std::uint8_t* oracle_signature,
                               std::uint8_t* oracle_shared, std::uint8_t* oracle_ecdsa_pkcs8,
                               std::uint8_t* oracle_ecdh_pkcs8, std::uint8_t* oracle_spki,
                               std::uint8_t* oracle_raw, int* sizes, int* verified), {
    try {
        const private_der = HEAPU8.slice(pkcs8, pkcs8 + 138);
        const raw = HEAPU8.slice(point, point + 65);
        const peer_raw = HEAPU8.slice(peer_point, peer_point + 65);
        const data = HEAPU8.slice(msg, msg + msg_size);
        const signature = HEAPU8.slice(sig, sig + 64);
        const low = HEAPU8.slice(normalized, normalized + 64);
        const subtle = globalThis.crypto.subtle;
        const ecdsa = {name: "ECDSA", namedCurve: "P-256"};
        const ecdh = {name: "ECDH", namedCurve: "P-256"};
        const with_sha256 = {name: "ECDSA", hash: "SHA-256"};
        const signer = await subtle.importKey("pkcs8", private_der, ecdsa, true, ["sign"]);
        const verifier = await subtle.importKey("raw", raw, ecdsa, true, ["verify"]);
        const ok = await subtle.verify(with_sha256, verifier, signature, data);
        const ok_low = await subtle.verify(with_sha256, verifier, low, data);
        const signed = new Uint8Array(await subtle.sign(with_sha256, signer, data));
        const agreer = await subtle.importKey("pkcs8", private_der, ecdh, true, ["deriveBits"]);
        const peer = await subtle.importKey("raw", peer_raw, ecdh, true, []);
        const shared = new Uint8Array(
            await subtle.deriveBits({name: "ECDH", public: peer}, agreer, 256));
        const ecdsa_pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", signer));
        const ecdh_pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", agreer));
        const spki = new Uint8Array(await subtle.exportKey("spki", verifier));
        const exported_raw = new Uint8Array(await subtle.exportKey("raw", verifier));
        if (signed.length !== 64 || shared.length !== 32) {
            console.error("subtle (P-256): sizes " + signed.length + ", " + shared.length);
            return -1;
        }
        HEAPU8.set(signed, oracle_signature);
        HEAPU8.set(shared, oracle_shared);
        HEAPU8.set(ecdsa_pkcs8.slice(0, 138), oracle_ecdsa_pkcs8);
        HEAPU8.set(ecdh_pkcs8.slice(0, 138), oracle_ecdh_pkcs8);
        HEAPU8.set(spki.slice(0, 91), oracle_spki);
        HEAPU8.set(exported_raw.slice(0, 65), oracle_raw);
        HEAP32[sizes >> 2] = ecdsa_pkcs8.length;
        HEAP32[(sizes >> 2) + 1] = ecdh_pkcs8.length;
        HEAP32[(sizes >> 2) + 2] = spki.length;
        HEAP32[(sizes >> 2) + 3] = exported_raw.length;
        HEAP32[verified >> 2] = ok && ok_low ? 1 : 0;
        return 0;
    } catch (e) {
        console.error("subtle (P-256): " + e);
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
using scalar_bytes = std::array<std::uint8_t, p256::secret_key_size>;

#ifdef WEBCPP_TEST_CRYPTO_ORACLE_CORRUPTED
constexpr bool corrupted = true;
#else
constexpr bool corrupted = false;
#endif
// The signature case and the ECDH case whose bytes the corrupted program flips.
constexpr std::size_t corrupted_signature = 17;
constexpr std::size_t corrupted_ecdh = 42;

/** What a run found: the checks that agree, the ones that do not, by name and case. */
struct tally {
    std::size_t agreed = 0;
    std::size_t low_s = 0;
    std::vector<std::string> disagreed;

    void check(bool agrees, char const* name, std::size_t index) {
        if (agrees) {
            ++agreed;
        } else {
            disagreed.push_back(std::string(name) + " " + std::to_string(index));
            std::printf("case %zu: WebCrypto disagrees on %s\n", index, name);
        }
    }
};

/** A scalar our key pair takes: 32 bytes of the seeded generator, drawn again until 0 < d < n. */
scalar_bytes drawn_scalar(std::mt19937_64& rng) {
    for (;;) {
        scalar_bytes scalar{};
        for (auto& b : scalar) {
            b = static_cast<std::uint8_t>(rng() & 0xffU);
        }
        if (p256::keypair::make(scalar)) {
            return scalar;
        }
    }
}

bytes random_bytes(std::mt19937_64& rng, std::size_t min_size, std::size_t max_size) {
    bytes out(std::uniform_int_distribution<std::size_t>(min_size, max_size)(rng));
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(rng() & 0xffU);
    }
    return out;
}

std::array<std::uint8_t, p256::digest_size> sha256(std::span<std::uint8_t const> message) {
    std::array<std::uint8_t, p256::digest_size> out{};
    BOOST_TEST(webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(out, message).has_value());
    return out;
}

template <std::size_t N>
bytes bytes_of(std::array<std::uint8_t, N> const& array) {
    return {array.begin(), array.end()};
}

/** One case: its four checks into `found`. */
void one_case(std::mt19937_64& rng, std::size_t index, tally& found) {
    auto const scalar = drawn_scalar(rng);
    auto const peer_scalar = drawn_scalar(rng);
    // The first message is empty; the others cross SHA-256's block of 64 bytes.
    bytes const message = index == 0 ? bytes{} : random_bytes(rng, 1, 300);
    auto const pair = p256::keypair::make(scalar);
    auto const peer = p256::keypair::make(peer_scalar);
    BOOST_TEST(pair.has_value());
    BOOST_TEST(peer.has_value());
    if (!pair || !peer) {
        return;
    }
    auto const public_key = pair->public_key();
    auto const peer_public_key = peer->public_key();
    auto const digest = sha256(message);
    auto signature = pair->sign_ecdsa(digest);
    auto const shared = public_key && peer_public_key ? pair->ecdh_x(*peer_public_key)
                                                      : webcpp::crypto::error::backend_failure;
    std::array<std::uint8_t, p256::max_spki_size> spki{};
    std::array<std::uint8_t, p256::max_pkcs8_size> pkcs8{};
    BOOST_TEST(public_key && p256::encode_spki(*public_key, spki).has_value());
    BOOST_TEST(p256::encode_pkcs8(*pair, pkcs8).has_value());
    if (!BOOST_TEST(signature.has_value()) || !BOOST_TEST(shared.has_value())) {
        return;
    }
    BOOST_TEST(p256::verify_ecdsa(*signature, digest, *public_key).has_value());
    if (corrupted && index == corrupted_signature) {
        (*signature)[5] ^= 0x01U;
    }
    auto const normalized = p256::normalize_ecdsa(*signature);
    BOOST_TEST(normalized.has_value());
    auto const ours_x = shared->bytes();
    bytes expected_x(ours_x.begin(), ours_x.end());
    if (corrupted && index == corrupted_ecdh) {
        expected_x[7] ^= 0x01U;
    }
    auto const point = public_key->uncompressed();
    auto const peer_point = peer_public_key->uncompressed();

    std::array<std::uint8_t, p256::signature_size> oracle_signature{};
    std::array<std::uint8_t, p256::coordinate_size> oracle_shared{};
    std::array<std::uint8_t, p256::max_pkcs8_size> oracle_ecdsa_pkcs8{};
    std::array<std::uint8_t, p256::max_pkcs8_size> oracle_ecdh_pkcs8{};
    std::array<std::uint8_t, p256::max_spki_size> oracle_spki{};
    std::array<std::uint8_t, p256::public_key_size> oracle_raw{};
    std::array<int, 4> sizes{};
    int verified = 0;
    int const ran = subtle_p256(
        pkcs8.data(), point.data(), peer_point.data(), message.data(), message.size(),
        signature->data(), normalized ? normalized->data() : signature->data(),
        oracle_signature.data(), oracle_shared.data(), oracle_ecdsa_pkcs8.data(),
        oracle_ecdh_pkcs8.data(), oracle_spki.data(), oracle_raw.data(), sizes.data(), &verified);
    BOOST_TEST_EQ(ran, 0);

    found.check(ran == 0 && verified == 1, "WebCrypto verifies ours", index);
    bool const we_verify =
        ran == 0 && p256::verify_ecdsa(oracle_signature, digest, *public_key).has_value();
    found.check(we_verify, "we verify WebCrypto's", index);
    if (ran == 0 && p256::check_low_s(oracle_signature)) {
        ++found.low_s;
    }
    found.check(ran == 0 && bytes_of(oracle_shared) == expected_x, "ECDH", index);
    bool const same_formats = ran == 0 && sizes == std::array<int, 4>{138, 138, 91, 65} &&
                              oracle_ecdsa_pkcs8 == pkcs8 && oracle_ecdh_pkcs8 == pkcs8 &&
                              oracle_spki == spki && oracle_raw == point;
    if (!same_formats) {
        std::printf(
            "case %zu: sizes %d %d %d %d\n ours pkcs8 %s\n ECDSA pkcs8 %s\n ECDH pkcs8 %s\n"
            " ours spki %s\n their spki %s\n",
            index, sizes[0], sizes[1], sizes[2], sizes[3], test::to_hex(pkcs8).c_str(),
            test::to_hex(oracle_ecdsa_pkcs8).c_str(), test::to_hex(oracle_ecdh_pkcs8).c_str(),
            test::to_hex(spki).c_str(), test::to_hex(oracle_spki).c_str());
    }
    found.check(same_formats, "formats", index);
}

}  // namespace

int main() {
    std::printf("p256 webcrypto oracle: seed %llu\n", static_cast<unsigned long long>(seed));
    print_node_versions();
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 rng(seed);
    tally found;
    for (std::size_t i = 0; i < cases; ++i) {
        one_case(rng, i, found);
    }
    std::printf("WebCrypto's S low in %zu of %zu signatures\n", found.low_s, cases);
    std::printf("oracle ok %zu\n", found.agreed);
    if (corrupted) {
        BOOST_TEST_EQ(found.agreed, (4 * cases) - 2);
        BOOST_TEST(found.disagreed ==
                   (std::vector<std::string>{
                       "WebCrypto verifies ours " + std::to_string(corrupted_signature),
                       "ECDH " + std::to_string(corrupted_ecdh)}));
    } else {
        BOOST_TEST_EQ(found.agreed, 4 * cases);
    }
    return test::exit_status(boost::report_errors());
}
