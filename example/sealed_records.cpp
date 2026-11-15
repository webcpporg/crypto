// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Seals data in pieces two ways: one message in chunks with the incremental seal, and a stream
// as separate records, each bound to its position. Binding the record number stops an attacker
// from reordering, replaying or dropping records without being noticed.
// tag::program[]
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
using aead_type = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;

namespace {

// A record sealed alone: its bytes and its tag.
struct record {
    std::vector<std::uint8_t> data;
    std::array<std::uint8_t, 16> tag{};
};

// The record number, big-endian: it is both the IV's last 8 bytes and the additional data.
std::array<std::uint8_t, 8> number_bytes(std::uint64_t number) {
    std::array<std::uint8_t, 8> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[7 - i] = static_cast<std::uint8_t>(number >> (8U * i));
    }
    return out;
}

// A counter IV is safe because no number is ever used twice under one key.
std::array<std::uint8_t, 12> counter_iv(std::uint64_t number) {
    std::array<std::uint8_t, 12> iv{};
    auto const bytes = number_bytes(number);
    std::ranges::copy(bytes, iv.begin() + 4);
    return iv;
}

bool incremental() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    if (!crypto::random_device().fill(key) || !crypto::random_device().fill(iv)) {
        return false;
    }
    auto aead = aead_type::make(key);
    if (!aead) {
        return false;
    }
    std::array<std::uint8_t, 48> const original{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    auto buffer = original;
    std::string_view const header_text = "header";
    std::array<std::uint8_t, 6> header{};
    std::ranges::copy(header_text, header.begin());

    // tag::incremental[]
    // The header is authenticated up front, then the buffer is encrypted chunk by chunk in place.
    if (!aead->begin_seal(iv, header)) {
        return false;
    }
    std::span<std::uint8_t> const whole(buffer);
    for (std::size_t chunk = 0; chunk < 3; ++chunk) {
        if (!aead->update(whole.subspan(chunk * 16, 16))) {
            return false;
        }
    }
    auto const tag = aead->result();
    // end::incremental[]
    if (!tag || buffer == original) {
        return false;
    }
    // The receiver has no need of the chunks: one open does the whole buffer.
    std::span<std::uint8_t const> const tag_bytes(tag->data(), tag->size());
    if (!aead->open(iv, header, buffer, tag_bytes) || buffer != original) {
        return false;
    }
    std::printf("incremental seal opened whole: 3 chunks\n");
    return true;
}

bool records() {
    // A fresh random key per stream makes the counter IVs safe.
    std::array<std::uint8_t, 32> key{};
    if (!crypto::random_device().fill(key)) {
        return false;
    }
    auto aead = aead_type::make(key);
    if (!aead) {
        return false;
    }
    std::string_view const message = "records are sealed one by one, each with its own number";

    // tag::records[]
    std::vector<record> sent;
    std::size_t const piece = (message.size() + 2) / 3;
    for (std::uint64_t number = 0; number < 3; ++number) {
        auto const part = message.substr(number * piece, piece);
        record made;
        made.data.assign(part.begin(), part.end());
        auto const tag = aead->seal(counter_iv(number), number_bytes(number), made.data);
        if (!tag) {
            return false;
        }
        std::ranges::copy(*tag, made.tag.begin());
        sent.push_back(std::move(made));
    }

    std::string received;
    for (std::uint64_t number = 0; number < 3; ++number) {
        auto data = sent[number].data;
        if (!aead->open(counter_iv(number), number_bytes(number), data, sent[number].tag)) {
            return false;
        }
        received.append(data.begin(), data.end());
        std::printf("record %llu ok\n", static_cast<unsigned long long>(number));
    }
    // A record presented at another position fails: its number is part of what is authenticated.
    auto replayed = sent[2].data;
    auto const refused = aead->open(counter_iv(1), number_bytes(1), replayed, sent[2].tag);
    // end::records[]
    if (received != message || refused || refused.error() != crypto::error::authentication_failed) {
        return false;
    }
    std::printf("record 2 as record 1: authentication_failed\n");
    return true;
}

}  // namespace

int main() {
    return incremental() && records() ? 0 : 1;
}

// end::program[]
