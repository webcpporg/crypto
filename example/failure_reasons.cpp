// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Shows the three ways AES-GCM can refuse a message: a tampered ciphertext, a nonce of the wrong
// size and a tag of the wrong size. A program must tell the first from the others: only
// authentication_failed means someone changed the data, and open then wipes the plaintext so
// that no unauthenticated bytes are ever used.
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
using aead_type = crypto::ciphers::aes256_gcm;

namespace {

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

bool all_zero(std::span<std::uint8_t const> bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t b) { return b == 0; });
}

}  // namespace

int main() {
    // A demonstration key and nonce, so that the output is the same on every run; a real program
    // draws the key from random_device and never reuses a nonce under it.
    std::array<std::uint8_t, 32> key{};
    key.fill(0x2a);
    std::array<std::uint8_t, 12> nonce{};
    nonce.fill(0x07);
    std::string_view const text = "attack at dawn!";
    std::array<std::uint8_t, 15> sealed{};
    std::ranges::copy(text, sealed.begin());

    auto aead = aead_type::from_key(key);
    wipe(std::as_writable_bytes(std::span(key)));
    if (!aead) {
        return 1;
    }
    auto const tag = aead->seal(nonce, {}, sealed);
    if (!tag) {
        return 1;
    }
    std::span<std::uint8_t const> const tag_bytes(tag->data(), tag->size());

    // (a) One flipped bit in the ciphertext.
    auto tampered = sealed;
    tampered[3] ^= 1U;
    auto const opened = aead->open(nonce, {}, tampered, tag_bytes);
    // tag::branch[]
    if (opened) {
        return 1;
    }
    if (opened.error() == crypto::error::authentication_failed) {
        // Someone changed the data or used another key: drop the message.
        std::printf("tampered: authentication_failed%s\n",
                    all_zero(tampered) ? ", data zeroed" : "");
        std::string const message = opened.error().message();
        std::printf("message: %s\n", message.c_str());
    } else {
        // Anything else is a mistake of the caller, not an attack.
        return 1;
    }
    // end::branch[]
    if (!all_zero(tampered)) {
        return 1;
    }

    // (b) An empty nonce is refused before anything is touched.
    auto copy = sealed;
    auto const no_nonce = aead->open({}, {}, copy, tag_bytes);
    if (no_nonce || no_nonce.error() != crypto::error::invalid_nonce_size || copy != sealed) {
        return 1;
    }
    std::printf("empty nonce: invalid_nonce_size, data untouched\n");

    // (c) A tag of 15 bytes instead of 16.
    auto const short_tag = aead->open(nonce, {}, copy, tag_bytes.first(15));
    if (short_tag || short_tag.error() != crypto::error::invalid_tag_size) {
        return 1;
    }
    std::printf("short tag: invalid_tag_size\n");
    return 0;
}

// end::program[]
