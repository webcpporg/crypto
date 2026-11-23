// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A file-sharing app shares a file with a recipient it knows only by an X25519 public key: the
// file is sealed once in a secret box under a key drawn for this file, and that file key is
// sealed to the recipient's public key in a sealed box. The upload holds both; only the
// recipient's secret key opens the file key, and the file key opens the file. Prints what the
// recipient reads, the sizes on the wire, and the refusals of a changed upload and of another
// key pair.
// tag::program[]
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/hybrid/sealed_box.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
using crypto::ciphers::secretbox;
using crypto::hybrid::sealed_box;

namespace {

// What the app uploads: the sealed file key, the file's nonce and tag, and the sealed file.
struct upload {
    std::array<std::uint8_t, 32 + sealed_box::overhead> sealed_key{};
    std::array<std::uint8_t, secretbox<>::iv_size> nonce{};
    secretbox<>::result_type tag{};
    std::vector<std::uint8_t> file;
};

// tag::share[]
// The sender: a key for this file alone, the file in a secret box under it, the key sealed to
// the recipient.
bool share(crypto::random_device& device, std::span<std::uint8_t const> recipient_public_key,
           std::string_view contents, upload& out) {
    crypto::secret<32> file_key;
    if (!device.fill(file_key.writable()) || !device.fill(out.nonce)) {
        return false;
    }
    auto box = secretbox<>::from_key(file_key.bytes());
    if (!box) {
        return false;
    }
    out.file.assign(contents.begin(), contents.end());
    auto const tag = box->seal(out.nonce, {}, out.file);
    if (!tag) {
        return false;
    }
    out.tag = *tag;
    return sealed_box::seal(recipient_public_key, file_key.bytes(), out.sealed_key).has_value();
}

// end::share[]

// tag::receive[]
// The recipient: the file key out of the sealed box, then the file out of the secret box.
void receive(char const* who, std::span<std::uint8_t const> public_key,
             std::span<std::uint8_t const> secret_key, upload received) {
    crypto::secret<32> file_key;
    auto const key_opened =
        sealed_box::open(public_key, secret_key, received.sealed_key, file_key.writable());
    if (!key_opened) {
        std::string const reason = key_opened.error().message();
        std::printf("%s: the file key refused: %s\n", who, reason.c_str());
        return;
    }
    auto box = secretbox<>::from_key(file_key.bytes());
    if (!box) {
        return;
    }
    auto const opened = box->open(received.nonce, {}, received.file, received.tag);
    if (!opened) {
        std::string const reason = opened.error().message();
        std::printf("%s: the file refused: %s\n", who, reason.c_str());
        return;
    }
    std::printf("%s read: %.*s\n", who, static_cast<int>(received.file.size()),
                reinterpret_cast<char const*>(received.file.data()));
}

// end::receive[]

}  // namespace

int main() {
    crypto::random_device device;
    // The recipient's key pair, made once on the recipient's device; only the public key is
    // published.
    crypto::secret<32> secret_key;
    if (!device.fill(secret_key.writable())) {
        return 1;
    }
    auto const public_key = crypto::curves::x25519::public_key(secret_key.bytes());
    if (!public_key) {
        return 1;
    }

    upload sent;
    if (!share(device, *public_key, "quarterly report, draft 3", sent)) {
        return 1;
    }
    std::printf("on the wire: %zu bytes of sealed key, %zu of nonce, %zu of tag, %zu of file\n",
                sent.sealed_key.size(), sent.nonce.size(), sent.tag.size(), sent.file.size());
    receive("the recipient", *public_key, secret_key.bytes(), sent);

    // The storage service changes the file.
    upload changed = sent;
    changed.file[0] ^= 0x01U;
    receive("the recipient, the upload changed", *public_key, secret_key.bytes(), changed);
    // Someone else's key pair cannot open the file key.
    crypto::secret<32> other_secret;
    if (!device.fill(other_secret.writable())) {
        return 1;
    }
    auto const other_public = crypto::curves::x25519::public_key(other_secret.bytes());
    if (!other_public) {
        return 1;
    }
    receive("another key pair", *other_public, other_secret.bytes(), sent);
    return 0;
}

// end::program[]
