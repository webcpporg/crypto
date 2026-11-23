// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Seals data in pieces two ways: one message in chunks with the incremental seal, and a stream
// as separate records, each bound to its position and to whether it is the last. The number in
// the additional data stops records from being reordered or replayed at another position, and
// the last-record flag stops a stream from being cut short without being noticed. Each stream has
// a key of its own, drawn when the stream starts: the counter IVs 0, 1, 2 of one stream are safe
// only because no other stream seals under its key.
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>

#include <boost/system/result.hpp>

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

// A record sealed alone: its bytes and its tag.
struct record {
    std::vector<std::uint8_t> data;
    std::array<std::uint8_t, 16> tag{};
};

// The record number, big-endian: the IV's last 8 bytes, and the additional data's first 8.
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

// The additional data of a record: its number, then 1 for the last record of the stream and 0
// for every other, so that a stream cut after any record fails to open.
std::array<std::uint8_t, 9> record_data(std::uint64_t number, bool last) {
    std::array<std::uint8_t, 9> out{};
    std::ranges::copy(number_bytes(number), out.begin());
    out[8] = last ? 1 : 0;
    return out;
}

// Opens the records received, in order, the last of them as the last of the stream; the first
// failure ends the stream, with its error.
boost::system::result<std::string> open_stream(aead_type& aead, std::span<record const> received) {
    std::string text;
    for (std::uint64_t number = 0; number < received.size(); ++number) {
        auto data = received[number].data;
        bool const last = number + 1 == received.size();
        auto const opened =
            aead.open(counter_iv(number), record_data(number, last), data, received[number].tag);
        if (!opened) {
            return opened.error();
        }
        text.append(data.begin(), data.end());
    }
    return text;
}

bool incremental() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    if (!crypto::random_device().fill(key) || !crypto::random_device().fill(iv)) {
        return false;
    }
    auto aead = aead_type::from_key(key);
    wipe(std::as_writable_bytes(std::span(key)));
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
    std::string_view const message = "records are sealed one by one, each with its own number";

    // tag::records[]
    // The stream's own key, drawn for it alone: every stream numbers its records from 0, so two
    // streams under one key would seal record 0 twice with one IV. The receiver gets this key
    // from the protocol, for example sealed under a long-lived key or agreed with ECDH.
    std::array<std::uint8_t, 32> key{};
    if (!crypto::random_device().fill(key)) {
        return false;
    }
    auto aead = aead_type::from_key(key);
    wipe(std::as_writable_bytes(std::span(key)));
    if (!aead) {
        return false;
    }

    std::vector<record> sent;
    std::size_t const piece = (message.size() + 2) / 3;
    for (std::uint64_t number = 0; number < 3; ++number) {
        auto const part = message.substr(number * piece, piece);
        record made;
        made.data.assign(part.begin(), part.end());
        bool const last = number == 2;
        auto const tag = aead->seal(counter_iv(number), record_data(number, last), made.data);
        if (!tag) {
            return false;
        }
        std::ranges::copy(*tag, made.tag.begin());
        sent.push_back(std::move(made));
    }

    // The whole stream opens, record by record.
    auto const whole = open_stream(*aead, sent);
    if (!whole || *whole != message) {
        return false;
    }
    std::printf("3 records opened, the last as the last\n");

    // A record presented at another position fails: its number is authenticated.
    auto moved = sent[2].data;
    auto const reordered = aead->open(counter_iv(1), record_data(1, false), moved, sent[2].tag);

    // A stream cut after record 1 fails: record 1 was not sealed as the last.
    auto const truncated = open_stream(*aead, std::span<record const>(sent).first(2));
    // end::records[]
    if (reordered || reordered.error() != crypto::error::authentication_failed || truncated ||
        truncated.error() != crypto::error::authentication_failed) {
        return false;
    }
    std::printf("record 2 as record 1: authentication_failed\n");
    std::printf("stream cut after record 1: authentication_failed\n");
    return true;
}

}  // namespace

int main() {
    return incremental() && records() ? 0 : 1;
}

// end::program[]
