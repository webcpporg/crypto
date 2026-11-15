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

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

std::array<std::uint8_t, 32> sha256(std::string_view text) {
    boost::hash2::sha2_256 hash;
    hash.update(text.data(), text.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> out{};
    std::copy_n(digest.data(), out.size(), out.begin());
    return out;
}

boost::system::result<secp256k1::keypair> generate_key() {
    crypto::random_device device;
    std::array<std::uint8_t, 32> secret{};
    for (;;) {
        auto const filled = device.fill(secret);
        if (!filled) {
            return filled.error();
        }
        auto key = secp256k1::keypair::make(secret);
        if (key || key.error() != crypto::error::invalid_secret_key) {
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
    auto const shipped_key = publisher->public_key();
    std::string update = "update v2.1 payload";
    auto const signature = publisher->sign_ecdsa(sha256(update));
    if (!shipped_key || !signature) {
        return 1;
    }

    // tag::verify[]
    // The program hashes the bytes it downloaded and checks the signature against the hash.
    if (!secp256k1::verify_ecdsa(*signature, sha256(update), *shipped_key)) {
        return 1;
    }
    std::printf("update accepted\n");

    update[7] = update[7] == '2' ? '3' : '2';
    auto const tampered = secp256k1::verify_ecdsa(*signature, sha256(update), *shipped_key);
    if (tampered || tampered.error() != crypto::error::invalid_signature) {
        return 1;
    }
    std::printf("tampered update refused: invalid_signature\n");
    // end::verify[]
    return 0;
}

// end::program[]
