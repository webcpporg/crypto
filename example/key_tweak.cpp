// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A watch-only wallet: a server that holds the wallet's public key and no secret gives each
// payment a fresh key, and the signing device, which holds the secret, derives the same keys'
// secrets. Both add the same tweak, one to the public key and one to the secret key; the
// device's tweaked key pair signs (BIP 340), and the signature verifies under the server's
// tweaked public key. The tweak here is an HMAC-SHA-256 of the public key and the payment's
// number under a chain code both sides share and no one else sees; BIP 32 derives such tweaks
// its own way, with HMAC-SHA-512, and is a domain library's.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/hash2/sha2.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <type_traits>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace hash2 = boost::hash2;

namespace {

// Overwrites an object's bytes through a volatile pointer, which the optimiser cannot drop as a
// dead store: crypto wipes its own copies of keys this way, and the program wipes its own.
template <class T>
void wipe(T& object) {
    static_assert(std::is_trivially_destructible_v<T>, "an object whose bytes are all its state");
    auto* const data = reinterpret_cast<unsigned char volatile*>(&object);
    for (std::size_t i = 0; i < sizeof(T); ++i) {
        data[i] = 0;
    }
}

// 32 secret bytes the program holds, wiped when the scope ends, on every path, an early return's
// included.
struct wiped_bytes {
    std::array<std::uint8_t, 32> bytes{};

    wiped_bytes() = default;
    wiped_bytes(wiped_bytes const&) = delete;
    wiped_bytes& operator=(wiped_bytes const&) = delete;

    ~wiped_bytes() { wipe(bytes); }
};

// The tweak of payment `number`: HMAC-SHA-256 under the chain code of the compressed public key
// and the number, written into `tweak`. Both sides compute it; an outsider without the chain
// code cannot, and so cannot tell that two payment keys belong to one wallet. The HMAC's state,
// keyed by the chain code, and its digest, the tweak itself, are wiped before it returns.
void payment_tweak(std::span<std::uint8_t const, 32> chain_code,
                   std::span<std::uint8_t const, 33> public_key, std::uint32_t number,
                   wiped_bytes& tweak) {
    hash2::hmac_sha2_256 mac(chain_code.data(), chain_code.size());
    mac.update(public_key.data(), public_key.size());
    std::array<std::uint8_t, 4> const index{
        static_cast<std::uint8_t>(number >> 24U),
        static_cast<std::uint8_t>(number >> 16U),
        static_cast<std::uint8_t>(number >> 8U),
        static_cast<std::uint8_t>(number),
    };
    mac.update(index.data(), index.size());
    auto digest = mac.result();
    std::copy_n(digest.data(), tweak.bytes.size(), tweak.bytes.begin());
    wipe(digest);
    wipe(mac);
}

}  // namespace

int main() {
    // The device's secret and the chain code, drawn once; the device keeps both, the server
    // gets the chain code and the public key.
    crypto::random_device device;
    wiped_bytes secret;
    wiped_bytes chain_code;
    if (!device.fill(secret.bytes) || !device.fill(chain_code.bytes)) {
        return 1;
    }
    auto const wallet = secp256k1::keypair::make(secret.bytes);
    if (!wallet) {
        // A secret not below the group order: negligible, and a real wallet draws again.
        return 1;
    }
    auto const wallet_public = wallet->public_key();
    if (!wallet_public) {
        return 1;
    }
    // The tweak and the tweaked secret give back the secret: the tweak is wiped too.
    wiped_bytes tweak;
    payment_tweak(chain_code.bytes, *wallet_public, 7, tweak);

    // The server: the wallet's public key plus the tweak, with no secret anywhere.
    auto const parsed = secp256k1::parse_public_key(*wallet_public);
    if (!parsed) {
        return 1;
    }
    auto const watched = secp256k1::pubkey_tweak_add(*parsed, tweak.bytes);

    // The device: the secret key plus the same tweak, a secret<32> it makes a key pair of.
    auto const tweaked_secret = secp256k1::seckey_tweak_add(secret.bytes, tweak.bytes);
    if (!watched || !tweaked_secret) {
        return 1;
    }
    auto const payment_key = secp256k1::keypair::make(tweaked_secret->bytes());
    if (!payment_key) {
        return 1;
    }
    auto const payment_public = payment_key->public_key();
    if (!payment_public || secp256k1::serialize_public_key(*watched) != *payment_public) {
        return 1;
    }
    std::printf("tweaked keys match\n");

    // The device signs a spend with the payment's key pair; the server verifies under the
    // x-only form of the key it derived alone (the compressed key without its prefix byte).
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> aux{};
    if (!device.fill(aux)) {
        return 1;
    }
    auto const signature = payment_key->sign(crypto::schnorr, message, aux);
    auto const watched_bytes = secp256k1::serialize_public_key(*watched);
    std::array<std::uint8_t, 32> xonly{};
    std::copy_n(watched_bytes.begin() + 1, xonly.size(), xonly.begin());
    if (!signature || !crypto::verify(crypto::schnorr, *signature, message, xonly)) {
        return 1;
    }
    std::printf("signature verifies under the tweaked public key\n");
    return 0;
}

// end::program[]
