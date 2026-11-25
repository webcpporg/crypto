// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Checks an update with the publisher's ECDSA signature before installing it. The public key is
// shipped inside the program, so a tampered download, or one from a mirror that is not the
// publisher, fails the check and is never run.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// A text's bytes, the message: ECDSA over SHA-256 hashes it inside the call.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

boost::system::result<secp256k1::keypair> generate_key() {
    crypto::random_device device;
    std::array<std::uint8_t, 32> secret{};
    for (;;) {
        auto const filled = device.fill(secret);
        if (!filled) {
            return filled.error();
        }
        auto key = secp256k1::keypair::from_secret(secret);
        if (key || key.error() != crypto::error::invalid_secret_key) {
            // The key pair keeps its own copy, which it wipes; this one goes now.
            secure::erase_secret(secret);
            return key;
        }
    }
}

}  // namespace

int main() {
    // The publisher signs once, offline; the secret never leaves the publisher.
    auto publisher = generate_key();
    if (!publisher) {
        return 1;
    }
    // The compressed public key (33 bytes) is what the program ships with.
    auto const publisher_public = publisher->public_key();
    std::string update = "update v2.1 payload";
    auto const signature = publisher->sign(crypto::ecdsa_sha256, bytes_of(update));
    if (!publisher_public || !signature) {
        return 1;
    }
    auto const shipped_key = publisher_public->compressed();

    // tag::verify[]
    // The program makes the key it ships with once, then checks the signature against the bytes
    // it downloaded, which crypto::verify hashes with SHA-256.
    auto const publisher_key = secp256k1::public_key::from_bytes(shipped_key);
    if (!publisher_key ||
        !crypto::verify(crypto::ecdsa_sha256, *signature, bytes_of(update), *publisher_key)) {
        return 1;
    }
    std::printf("update accepted\n");

    update[7] = update[7] == '2' ? '3' : '2';
    auto const tampered =
        crypto::verify(crypto::ecdsa_sha256, *signature, bytes_of(update), *publisher_key);
    if (tampered || tampered.error() != crypto::error::invalid_signature) {
        return 1;
    }
    std::printf("tampered update refused: invalid_signature\n");
    // end::verify[]
    return 0;
}

// end::program[]
