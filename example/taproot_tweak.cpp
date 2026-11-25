// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Tweaks an internal key as Bitcoin's Taproot does for a key-path-only output (BIP341): the
// tweak is a tagged hash of the internal key, and the output key commits to it. The same tweak
// applied to the key pair lets the owner sign for the output key, so spending needs no script.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/constant_time_equal.hpp>

#include <boost/hash2/sha2.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (std::uint8_t const b : bytes) {
        std::printf("%02x", b);
    }
    std::printf("\n");
}

// BIP340's tagged hash: SHA-256(SHA-256(tag) || SHA-256(tag) || data). The tag separates the
// uses of the hash, so that a hash made for one purpose is never valid for another.
std::array<std::uint8_t, 32> tagged_hash(std::string_view tag, std::span<std::uint8_t const> data) {
    boost::hash2::sha2_256 tag_hash;
    tag_hash.update(tag.data(), tag.size());
    auto const prefix = tag_hash.result();

    boost::hash2::sha2_256 hash;
    hash.update(prefix.data(), prefix.size());
    hash.update(prefix.data(), prefix.size());
    hash.update(data.data(), data.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> out{};
    std::copy_n(digest.data(), out.size(), out.begin());
    return out;
}

}  // namespace

int main() {
    // BIP340's first test vector key, public on purpose; a real secret is drawn from
    // random_device.
    std::array<std::uint8_t, 32> secret{};
    secret.back() = 0x03;
    auto key = secp256k1::keypair::from_secret(secret);
    wipe(std::as_writable_bytes(std::span(secret)));
    if (!key) {
        return 1;
    }
    auto const internal_public = key->public_key();
    if (!internal_public) {
        return 1;
    }
    auto const internal_key = internal_public->xonly();

    // tag::tweak[]
    // The tweak is the domain library's business; the library only applies it.
    auto const tweak = tagged_hash("TapTweak", internal_key);
    auto const output = secp256k1::tweak_xonly(internal_key, tweak);
    if (!output) {
        return 1;
    }
    print("output key", output->key);
    std::printf("parity %d\n", output->parity);
    // end::tweak[]

    // tag::spend[]
    // The owner applies the same tweak to the key pair and signs for the output key.
    if (!key->tweak_xonly(tweak)) {
        return 1;
    }
    auto const tweaked_public = key->public_key();
    if (!tweaked_public || !secure::constant_time_equal(tweaked_public->xonly(), output->key)) {
        return 1;
    }
    std::printf("key pair tweaked: same output key\n");

    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    auto const signature = key->sign(crypto::schnorr, message, aux);
    if (!signature || !crypto::verify(crypto::schnorr, *signature, message, output->key)) {
        return 1;
    }
    std::printf("key-path signature verified\n");
    // end::spend[]
    return 0;
}

// end::program[]
