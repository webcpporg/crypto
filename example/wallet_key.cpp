// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Makes a wallet's key pair from a random secret, then seals the secret at rest with AES-256-GCM
// and restores it. A secret that sits unencrypted on disk, or lingers in memory after use, is
// the first thing an attacker looks for, so the copies are wiped as soon as they are not needed.
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/secure/constant_time_equal.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
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

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

}  // namespace

int main() {
    crypto::random_device device;

    // tag::keygen[]
    std::array<std::uint8_t, 32> secret{};
    boost::system::result<secp256k1::keypair> wallet = crypto::error::backend_failure;
    for (;;) {
        if (!device.fill(secret)) {
            return 1;
        }
        wallet = secp256k1::keypair::from_secret(secret);
        // A secret that is zero or too large is refused: draw again. Other errors are real.
        if (wallet) {
            break;
        }
        if (wallet.error() != crypto::error::invalid_secret_key) {
            return 1;
        }
    }
    auto const public_key = wallet->public_key();
    if (!public_key) {
        return 1;
    }
    auto const xonly = public_key->xonly();
    auto const compressed = public_key->compressed();
    std::printf("key pair made\n");
    std::printf("x-only public key: %zu bytes\n", xonly.size());
    // The compressed form starts with 0x02 (even y) or 0x03 (odd y).
    bool const prefix_ok = compressed[0] == 0x02 || compressed[0] == 0x03;
    std::printf("compressed public key: %zu bytes, prefix %s\n", compressed.size(),
                prefix_ok ? "ok" : "BAD");
    // end::keygen[]
    if (!prefix_ok) {
        return 1;
    }

    // tag::seal[]
    // The device key is separate from the wallet and lives elsewhere, such as the OS keystore.
    std::array<std::uint8_t, 32> device_key{};
    std::array<std::uint8_t, 12> nonce{};
    if (!device.fill(device_key) || !device.fill(nonce)) {
        return 1;
    }
    auto aead = crypto::ciphers::aes256_gcm::from_key(device_key);
    wipe(std::as_writable_bytes(std::span(device_key)));
    if (!aead) {
        return 1;
    }
    auto stored = secret;
    wipe(std::as_writable_bytes(std::span(secret)));
    // "wallet v1" ties the ciphertext to its purpose and format version.
    auto const tag = aead->seal(nonce, bytes_of("wallet v1"), stored);
    if (!tag) {
        return 1;
    }

    // Later: open the stored secret and make the key pair again.
    if (!aead->open(nonce, bytes_of("wallet v1"), stored,
                    std::span<std::uint8_t const>(tag->data(), tag->size()))) {
        return 1;
    }
    auto restored = secp256k1::keypair::from_secret(stored);
    wipe(std::as_writable_bytes(std::span(stored)));
    if (!restored) {
        return 1;
    }
    auto const restored_key = restored->public_key();
    if (!restored_key || *restored_key != *public_key) {
        return 1;
    }
    std::printf("secret sealed and restored: same public key\n");
    // end::seal[]
    return 0;
}

// end::program[]
