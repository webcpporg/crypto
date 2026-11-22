// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An audit record sealed and opened through an event loop: the GCM specification's test case 16
// (AES-256, 12-byte IV, additional data), a published key, never a real one. Each completion runs
// from the loop's run, after the call that started it has returned, on every target; the handler
// of the seal prints the tag and starts the open, the handler of the open compares the plaintext.
// The loop ends when no operation is pending: nothing waits for a time.
// tag::program[]
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
using aead_type = crypto::ciphers::aes256_gcm;

namespace {

// The bytes a string of hex digits writes, two per byte.
std::vector<std::uint8_t> bytes_of(std::string_view hex) {
    auto const digit = [](char c) {
        return static_cast<std::uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
    };
    std::vector<std::uint8_t> bytes(hex.size() / 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((digit(hex[2 * i]) << 4U) | digit(hex[(2 * i) + 1]));
    }
    return bytes;
}

void print(char const* name, std::span<std::uint8_t const> bytes) {
    std::printf("%s ", name);
    for (std::uint8_t const byte : bytes) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
}

}  // namespace

int main() {
    auto const key = bytes_of("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    auto const iv = bytes_of("cafebabefacedbaddecaf888");
    auto const additional_data = bytes_of("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    auto const record = bytes_of(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449"
        "a6b525b16aedf5aa0de657ba637b39");

    asio::io_context loop;
    // What a call reads and writes is the program's until the completion: the key, the IV, the
    // additional data and the record outlive the loop's run. The record is sealed in place.
    std::vector<std::uint8_t> data = record;
    std::optional<aead_type> aead;
    bool returned = false;
    int status = 1;

    crypto::async_make<aead_type>(
        loop.get_executor(), key, [&](boost::system::error_code made, aead_type keyed) {
            if (made) {
                std::printf("make: %s\n", made.message().c_str());
                return;
            }
            aead.emplace(std::move(keyed));
            std::printf("made after the call returned: %s\n", returned ? "yes" : "no");
            crypto::async_seal(
                loop.get_executor(), *aead, iv, additional_data, data,
                [&](boost::system::error_code sealed, aead_type::result_type digest) {
                    if (sealed) {
                        std::printf("seal: %s\n", sealed.message().c_str());
                        return;
                    }
                    std::array<std::uint8_t, aead_type::tag_size> tag{};
                    std::ranges::copy(digest, tag.begin());
                    print("tag", tag);
                    // The ciphertext replaced the record, and the tag opens it back.
                    crypto::async_open(loop.get_executor(), *aead, iv, additional_data, data, tag,
                                       [&](boost::system::error_code opened) {
                                           if (opened) {
                                               std::printf("open: %s\n", opened.message().c_str());
                                               return;
                                           }
                                           bool const same = std::ranges::equal(data, record);
                                           std::printf("opened, the record is back: %s\n",
                                                       same ? "yes" : "no");
                                           status = same ? 0 : 1;
                                       });
                });
        });
    returned = true;
    loop.run();  // lint-run: the program's event loop
    return status;
}

// end::program[]
