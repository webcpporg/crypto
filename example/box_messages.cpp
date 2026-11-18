// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two people who know each other's X25519 public keys exchange messages in libsodium's box:
// each makes a box from the own secret key and the other's public key, agreeing one key for the
// pair, then seals each message with a nonce drawn at random. What one seals the other opens; a
// stranger's box, from another key pair, does not. Prints what each reads.
// tag::program[]
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
using crypto::hybrid::box;

namespace {

// A person's X25519 key pair: the secret key stays, the public key is published.
struct person {
    crypto::secret<32> secret_key;
    std::array<std::uint8_t, 32> public_key{};

    static std::optional<person> make(crypto::random_device& device) {
        person made;
        if (!device.fill(made.secret_key.writable())) {
            return std::nullopt;
        }
        auto const public_key = crypto::curves::x25519::public_key(made.secret_key.bytes());
        if (!public_key) {
            return std::nullopt;
        }
        made.public_key = *public_key;
        return made;
    }
};

// A message as it travels: the nonce, the tag and the ciphertext.
struct sealed_message {
    std::array<std::uint8_t, box::iv_size> nonce{};
    box::result_type tag{};
    std::vector<std::uint8_t> ciphertext;
};

// tag::exchange[]
bool send(box& sender, crypto::random_device& device, std::string_view text, sealed_message& out) {
    if (!device.fill(out.nonce)) {
        return false;
    }
    out.ciphertext.assign(text.begin(), text.end());
    auto const tag = sender.seal(out.nonce, out.ciphertext);
    if (!tag) {
        return false;
    }
    out.tag = *tag;
    return true;
}

void read(char const* who, box& recipient, sealed_message message) {
    auto const opened = recipient.open(message.nonce, message.ciphertext, message.tag);
    if (!opened) {
        std::printf("%s refused it: %s\n", who, opened.error().message().c_str());
        return;
    }
    std::printf("%s read: %.*s\n", who, static_cast<int>(message.ciphertext.size()),
                reinterpret_cast<char const*>(message.ciphertext.data()));
}

// end::exchange[]

}  // namespace

int main() {
    crypto::random_device device;
    auto alice = person::make(device);
    auto bob = person::make(device);
    auto mallory = person::make(device);
    if (!alice || !bob || !mallory) {
        return 1;
    }
    // tag::boxes[]
    // Each side's box: the own secret key and the other's public key give the same key.
    auto alice_box = box::make(alice->secret_key.bytes(), bob->public_key);
    auto bob_box = box::make(bob->secret_key.bytes(), alice->public_key);
    // end::boxes[]
    auto mallory_box = box::make(mallory->secret_key.bytes(), alice->public_key);
    if (!alice_box || !bob_box || !mallory_box) {
        return 1;
    }
    sealed_message to_bob;
    sealed_message to_alice;
    if (!send(*alice_box, device, "the meeting moved to Friday", to_bob) ||
        !send(*bob_box, device, "Friday works", to_alice)) {
        return 1;
    }
    read("Bob", *bob_box, to_bob);
    read("Alice", *alice_box, to_alice);
    // Mallory, who knows Alice's public key, holds another key pair: not the pair's key.
    read("Mallory", *mallory_box, to_bob);
    return 0;
}

// end::program[]
