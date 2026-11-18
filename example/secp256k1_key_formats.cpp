// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A server's secp256k1 key in files that OpenSSL also reads: its public key written as PEM SPKI
// for a configuration file that its clients read, and read back; its key pair written as PEM
// PKCS#8 for the server's own key file, which is never printed, and read back. The secret is
// the fixed 0x11 repeated, so that the output is fixed: a real server draws its own.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace pem = webcpp::crypto::pem;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;

namespace {

// The public key as PEM SPKI, compressed, printed as the configuration file holds it, and read
// back from that text: the same key.
bool public_key_to_pem(secp256k1::public_key const& key) {
    std::array<std::uint8_t, secp256k1::max_spki_size> spki{};
    auto const size = secp256k1::encode_spki(key, spki);
    if (!size) {
        return false;
    }
    std::array<char, pem::armoured_size(pem::public_key_label.size(), secp256k1::max_spki_size)>
        text{};
    auto const written = pem::armour(pem::public_key_label, std::span(spki).first(*size), text);
    if (!written) {
        return false;
    }
    std::string_view const config(text.data(), *written);
    std::printf("%.*s", static_cast<int>(config.size()), config.data());

    std::array<std::uint8_t, secp256k1::max_spki_size> read{};
    auto const read_size = pem::unarmour(pem::public_key_label, config, read);
    if (!read_size) {
        return false;
    }
    auto const back = secp256k1::decode_spki(std::span(read).first(*read_size));
    return back && *back == key;
}

// The key pair as PEM PKCS#8, which holds the secret: the DER and the text are kept in
// secret<N>, which wipes itself, the text as its bytes' characters. Read back, it is a key pair
// of the same public key.
bool key_pair_to_pem(secp256k1::keypair const& key_pair) {
    crypto::secret<secp256k1::max_pkcs8_size> pkcs8;
    auto const size = secp256k1::encode_pkcs8(key_pair, pkcs8.writable());
    if (!size) {
        return false;
    }
    crypto::secret<pem::armoured_size(pem::private_key_label.size(), secp256k1::max_pkcs8_size)>
        file;
    std::span<char> const text(reinterpret_cast<char*>(file.writable().data()), file.size());
    auto const written = pem::armour(pem::private_key_label, pkcs8.bytes().first(*size), text);
    if (!written) {
        return false;
    }

    crypto::secret<secp256k1::max_pkcs8_size> read;
    auto const read_size = pem::unarmour(pem::private_key_label,
                                         std::string_view(text.data(), *written), read.writable());
    if (!read_size) {
        return false;
    }
    auto const back = secp256k1::decode_pkcs8(read.bytes().first(*read_size));
    if (!back) {
        return false;
    }
    auto const back_key = back->public_key();
    auto const original_key = key_pair.public_key();
    return back_key && original_key && *back_key == *original_key;
}

// The server's files written and read back.
bool store_and_read(secp256k1::keypair const& key_pair) {
    auto const encoded = key_pair.public_key();
    if (!encoded) {
        return false;
    }
    auto const key = secp256k1::parse_public_key(*encoded);
    return key && public_key_to_pem(*key) && key_pair_to_pem(key_pair);
}

}  // namespace

int main() {
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(0x11);
    auto const key_pair = secp256k1::keypair::make(secret_key);
    if (!key_pair || !store_and_read(*key_pair)) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("read back: same key\n");
    return 0;
}

// end::program[]
