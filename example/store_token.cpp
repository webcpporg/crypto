// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Stores a user's API token encrypted in a database row, bound to the user's id. The id is
// additional data: authenticated but not encrypted, so a row copied to another user's record
// no longer opens. Without that binding a database writer could swap the rows of two users.
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/random_device.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

// What the database holds: the IV and the tag are not secret, only the key is.
struct row {
    std::array<std::uint8_t, 12> iv{};
    std::vector<std::uint8_t> ciphertext;
    std::array<std::uint8_t, 16> tag{};
};

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // The text's characters are the bytes to authenticate.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

}  // namespace

int main() {
    crypto::random_device device;
    // The storage key lives outside the database, in a secrets store.
    std::array<std::uint8_t, 32> storage_key{};
    if (!device.fill(storage_key)) {
        return 1;
    }
    auto aead = aead_type::make(storage_key);
    // The object keeps its own key schedule, which it wipes; this copy goes now.
    wipe(std::as_writable_bytes(std::span(storage_key)));
    if (!aead) {
        return 1;
    }

    // tag::seal[]
    std::string_view const token = "api-token-0123456789";
    row stored;
    // A fresh IV for every row: reusing one under the same key breaks GCM.
    if (!device.fill(stored.iv)) {
        return 1;
    }
    stored.ciphertext.assign(token.begin(), token.end());
    auto const tag = aead->seal(stored.iv, bytes_of("user-42"), stored.ciphertext);
    if (!tag) {
        return 1;
    }
    std::ranges::copy(*tag, stored.tag.begin());
    // end::seal[]

    // tag::open[]
    // Reading the row back: the id comes from the session, not from the row.
    auto plain = stored.ciphertext;
    if (!aead->open(stored.iv, bytes_of("user-42"), plain, stored.tag)) {
        return 1;
    }
    std::printf("opened for user-42: %.*s\n", static_cast<int>(plain.size()),
                reinterpret_cast<char const*>(plain.data()));
    // end::open[]

    // The same row copied to user 43's record does not open.
    plain = stored.ciphertext;
    auto const stolen = aead->open(stored.iv, bytes_of("user-43"), plain, stored.tag);
    if (stolen || stolen.error() != crypto::error::authentication_failed) {
        return 1;
    }
    std::printf("refused for user-43: authentication_failed\n");
    return 0;
}

// end::program[]
