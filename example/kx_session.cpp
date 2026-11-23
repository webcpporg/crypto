// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A chat app's client and server, each with a crypto_kx key pair made from libsodium's kx test's
// seeds, exchange public keys and compute their session keys; the client seals a message with
// its transmit key and the server opens it with its receive key, on ChaCha20-Poly1305; a peer key
// of low order is refused. Prints the public keys and the client's session keys in hex.
// tag::program[]
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

namespace crypto = webcpp::crypto;
namespace key_exchange = webcpp::crypto::key_exchange;

namespace {

// Prints bytes in hex after a name.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (auto const byte : bytes) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
}

// The client sends "hello" to the server, sealed with the client's transmit key and opened with
// the server's receive key, the same key.
bool message(key_exchange::session_keys const& client, key_exchange::session_keys const& server) {
    auto sealer = crypto::ciphers::chacha20_poly1305<>::from_key(client.transmit.bytes());
    auto opener = crypto::ciphers::chacha20_poly1305<>::from_key(server.receive.bytes());
    if (!sealer || !opener) {
        return false;
    }
    // The first message of this direction: nonce 0. Each next message takes the next number;
    // a nonce is never used twice under one key.
    std::array<std::uint8_t, 12> const nonce{};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    auto const tag = sealer->seal(nonce, {}, data);
    if (!tag || !opener->open(nonce, {}, data, *tag)) {
        return false;
    }
    std::printf("server read   ");
    for (auto const byte : data) {
        std::printf("%c", byte);
    }
    std::printf("\n");
    return true;
}

bool client_and_server() {
    // libsodium's kx test's seeds, published, never real ones: a program calls
    // kx_keypair<>::generate(), which draws its seed with random_device.
    std::array<std::uint8_t, 32> client_seed{};
    for (std::size_t i = 0; i < client_seed.size(); ++i) {
        client_seed[i] = static_cast<std::uint8_t>(i);
    }
    std::array<std::uint8_t, 32> server_seed = client_seed;
    server_seed[0] = 1;
    auto const client = key_exchange::kx_keypair<>::derive_from_seed(client_seed);
    auto const server = key_exchange::kx_keypair<>::derive_from_seed(server_seed);
    if (!client || !server) {
        return false;
    }
    // Each side sends its public key; the secret keys never leave the key pairs.
    auto const client_public = client->public_key();
    auto const server_public = server->public_key();
    if (!client_public || !server_public) {
        return false;
    }
    print("client public", *client_public);
    print("server public", *server_public);
    auto const client_keys = client->client_session_keys(*server_public);
    auto const server_keys = server->server_session_keys(*client_public);
    if (!client_keys || !server_keys) {
        return false;
    }
    // Printed here only because libsodium's test publishes them; a program never prints a key.
    print("client rx    ", client_keys->receive.bytes());
    print("client tx    ", client_keys->transmit.bytes());
    return crypto::equal(client_keys->transmit.bytes(), server_keys->receive.bytes()) &&
           crypto::equal(client_keys->receive.bytes(), server_keys->transmit.bytes()) &&
           message(*client_keys, *server_keys);
}

// A peer key of low order gives an all-zero X25519 secret, which crypto_kx refuses.
bool low_order_refused() {
    auto const key = key_exchange::kx_keypair<>::derive_from_seed(std::array<std::uint8_t, 32>{});
    std::array<std::uint8_t, 32> const zero_point{};
    if (!key) {
        return false;
    }
    auto const keys = key->server_session_keys(zero_point);
    if (!keys && keys.error() == crypto::error::weak_public_key) {
        std::printf("low order     refused: weak_public_key\n");
        return true;
    }
    return false;
}

}  // namespace

int main() {
    if (!client_and_server() || !low_order_refused()) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("agreed\n");
    return 0;
}

// end::program[]
