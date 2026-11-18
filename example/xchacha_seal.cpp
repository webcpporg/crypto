// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A chat app, in the browser and natively alike, encrypts each message of a conversation under
// the conversation's key with XChaCha20-Poly1305, a fresh 24-byte nonce drawn at random per
// message and the conversation's id as additional data; a message changed on the way, or moved
// to another conversation, does not open. Prints what the recipient reads.
// tag::program[]
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
using xchacha = crypto::ciphers::xchacha20_poly1305<>;

namespace {

// A message as it travels: the nonce, the tag and the ciphertext, all public.
struct sealed_message {
    std::array<std::uint8_t, xchacha::iv_size> nonce{};
    xchacha::result_type tag{};
    std::vector<std::uint8_t> ciphertext;
};

// tag::seal[]
// Seals text under the conversation's key, with a nonce drawn for this message alone.
bool seal(xchacha& cipher, crypto::random_device& device, std::span<std::uint8_t const> id,
          std::string_view text, sealed_message& out) {
    if (!device.fill(out.nonce)) {
        return false;
    }
    out.ciphertext.assign(text.begin(), text.end());
    auto const tag = cipher.seal(out.nonce, id, out.ciphertext);
    if (!tag) {
        return false;
    }
    out.tag = *tag;
    return true;
}

// end::seal[]

// tag::open[]
// Opens a message in place; prints it, or why it was refused.
void open(xchacha& cipher, std::span<std::uint8_t const> id, sealed_message message) {
    auto const opened = cipher.open(message.nonce, id, message.ciphertext, message.tag);
    if (!opened) {
        std::printf("refused: %s\n", opened.error().message().c_str());
        return;
    }
    std::printf("read: %.*s\n", static_cast<int>(message.ciphertext.size()),
                reinterpret_cast<char const*>(message.ciphertext.data()));
}

// end::open[]

}  // namespace

int main() {
    crypto::random_device device;
    // The conversation's key: in a real app, agreed with the contact (curves::x25519) or
    // derived from a key the app already keeps; here, drawn once.
    crypto::secret<32> key;
    if (!device.fill(key.writable())) {
        return 1;
    }
    auto cipher = xchacha::make(key.bytes());
    if (!cipher) {
        return 1;
    }
    std::array<std::uint8_t, 8> const conversation{'c', 'h', 'a', 't', '-', '0', '4', '2'};
    std::array<std::uint8_t, 8> const other{'c', 'h', 'a', 't', '-', '0', '0', '7'};

    sealed_message first;
    sealed_message second;
    if (!seal(*cipher, device, conversation, "see you at noon", first) ||
        !seal(*cipher, device, conversation, "bring the keys", second)) {
        return 1;
    }
    open(*cipher, conversation, first);
    open(*cipher, conversation, second);

    // A relay flips one bit of the ciphertext.
    sealed_message changed = first;
    changed.ciphertext[0] ^= 0x01U;
    open(*cipher, conversation, changed);
    // A message replayed into another conversation.
    open(*cipher, other, second);
    return 0;
}

// end::program[]
