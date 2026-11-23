// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Opens a sealed file of 1 MiB without holding it whole, in two passes over the file: the first
// authenticates every piece of 64 KiB and verifies the tag, the second decrypts the same pieces.
// No byte of plaintext leaves the object before the tag matched. The file is any std::istream
// read twice: a program reads its own disk through a std::ifstream; this one keeps the file in a
// std::stringstream, so that it runs where the program has no directory (WASI).
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/random_device.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <istream>
#include <ostream>
#include <span>
#include <sstream>
#include <vector>

namespace crypto = webcpp::crypto;
using aead_type = crypto::ciphers::aes256_gcm;

namespace {

constexpr std::size_t file_size = std::size_t{1} << 20U;        // 1 MiB
constexpr std::size_t file_piece_size = std::size_t{1} << 16U;  // 64 KiB

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

// Reads the next piece of the file into `piece`: the bytes read, 0 at its end.
std::span<std::uint8_t> read_piece(std::istream& file, std::vector<std::uint8_t>& piece) {
    file.read(reinterpret_cast<char*>(piece.data()), static_cast<std::streamsize>(piece.size()));
    return std::span(piece).first(static_cast<std::size_t>(file.gcount()));
}

// Seals a copy of `plain` in pieces into `file`, and returns the tag, which is stored beside the
// file.
boost::system::result<aead_type::result_type> seal_file(aead_type& aead,
                                                        std::span<std::uint8_t const> iv,
                                                        std::vector<std::uint8_t> plain,
                                                        std::ostream& file) {
    if (auto const begun = aead.begin_seal(iv, {}); !begun) {
        return begun.error();
    }
    for (std::size_t at = 0; at < plain.size(); at += file_piece_size) {
        auto const piece =
            std::span(plain).subspan(at, (std::min)(file_piece_size, plain.size() - at));
        if (auto const updated = aead.update(piece); !updated) {
            return updated.error();
        }
        file.write(reinterpret_cast<char const*>(piece.data()),
                   static_cast<std::streamsize>(piece.size()));
    }
    return aead.result();
}

// tag::open[]
// Opens the file in two passes, writing its plaintext to `plain`. The file must hold the same
// bytes in both: a program reads a file of its own disk that no one else writes meanwhile.
boost::system::result<void> open_file(aead_type& aead, std::span<std::uint8_t const> iv,
                                      std::span<std::uint8_t const> tag, std::istream& file,
                                      std::ostream& plain) {
    std::vector<std::uint8_t> piece(file_piece_size);
    // The first pass reads every piece, and writes none.
    if (auto const begun = aead.begin_open(iv, {}); !begun) {
        return begun.error();
    }
    std::size_t authenticated = 0;
    for (auto read = read_piece(file, piece); !read.empty(); read = read_piece(file, piece)) {
        if (auto const done = aead.authenticate(read); !done) {
            return done.error();
        }
        authenticated += read.size();
    }
    std::printf("authenticated %zu bytes\n", authenticated);
    if (auto const verified = aead.verify(tag); !verified) {
        return verified.error();  // nothing was decrypted
    }
    std::printf("tag verified\n");

    // The second pass reads the same bytes again, and decrypts them. When decrypt or end_open
    // fails, the plaintext written so far is to be discarded: the file changed between the
    // passes, or the backend failed, and those bytes are not the authenticated message.
    file.clear();
    file.seekg(0);
    std::size_t decrypted = 0;
    for (auto read = read_piece(file, piece); !read.empty(); read = read_piece(file, piece)) {
        if (auto const done = aead.decrypt(read); !done) {
            return done.error();
        }
        plain.write(reinterpret_cast<char const*>(read.data()),
                    static_cast<std::streamsize>(read.size()));
        decrypted += read.size();
    }
    std::printf("decrypted %zu bytes\n", decrypted);
    return aead.end_open();
}

// end::open[]

}  // namespace

int main() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> iv{};
    if (!crypto::random_device().fill(key) || !crypto::random_device().fill(iv)) {
        return 1;
    }
    auto aead = aead_type::from_key(key);
    wipe(std::as_writable_bytes(std::span(key)));
    if (!aead) {
        return 1;
    }
    std::vector<std::uint8_t> original(file_size);
    for (std::size_t i = 0; i < original.size(); ++i) {
        original[i] = static_cast<std::uint8_t>(i * 7);
    }

    std::stringstream file;  // a std::fstream of the program's own disk
    auto const tag = seal_file(*aead, iv, original, file);
    if (!tag) {
        return 1;
    }
    file.seekg(0);
    std::stringstream plain;  // another file of the program's own disk
    if (!open_file(*aead, iv, std::span(tag->data(), tag->size()), file, plain)) {
        return 1;
    }
    auto const text = plain.str();
    bool const equal = text.size() == original.size() &&
                       std::equal(original.begin(), original.end(), text.begin(),
                                  [](std::uint8_t original_byte, char read_byte) {
                                      return original_byte == static_cast<std::uint8_t>(read_byte);
                                  });
    std::printf("equal: %s\n", equal ? "yes" : "no");
    return equal ? 0 : 1;
}

// end::program[]
