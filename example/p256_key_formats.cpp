// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// RFC 6979's P-256 key in the files other programs read: its public key written as PEM SPKI,
// the text OpenSSL reads and whose DER a WebCrypto peer's importKey("spki") reads, printed and
// read back; its key pair written as PEM PKCS#8 for the program's own key file, never
// printed, and read back. The key is RFC 6979's published one, so that the output is fixed: a
// real program draws its own.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/crypto/secret.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace crypto = webcpp::crypto;
namespace pem = webcpp::crypto::pem;
namespace p256 = webcpp::crypto::curves::p256;

namespace {

// The public key as PEM SPKI, printed as a configuration file holds it, and read back from that
// text: the same point.
bool public_key_to_pem(p256::public_key const& key) {
    std::array<std::uint8_t, p256::max_spki_size> spki{};
    auto const size = p256::encode_spki(key, spki);
    if (!size) {
        return false;
    }
    std::array<char, pem::armoured_size(pem::public_key_label.size(), p256::max_spki_size)> text{};
    auto const written = pem::armour(pem::public_key_label, std::span(spki).first(*size), text);
    if (!written) {
        return false;
    }
    std::string_view const file(text.data(), *written);
    std::printf("%.*s", static_cast<int>(file.size()), file.data());

    std::array<std::uint8_t, p256::max_spki_size> read{};
    auto const read_size = pem::unarmour(pem::public_key_label, file, read);
    if (!read_size) {
        return false;
    }
    auto const back = p256::decode_spki(std::span(read).first(*read_size));
    return back && back->uncompressed() == key.uncompressed();
}

// The key pair as PEM PKCS#8, which holds the scalar: the DER and the text are kept in
// secret<N>, which wipes itself, the text as its bytes' characters. Read back, it is a key pair
// of the same public key.
bool key_pair_to_pem(p256::keypair const& key_pair) {
    crypto::secret<p256::max_pkcs8_size> pkcs8;
    auto const size = p256::encode_pkcs8(key_pair, pkcs8.writable());
    if (!size) {
        return false;
    }
    constexpr std::size_t file_size =
        pem::armoured_size(pem::private_key_label.size(), p256::max_pkcs8_size);
    crypto::secret<file_size> file;
    std::span<char> const text(reinterpret_cast<char*>(file.writable().data()), file_size);
    auto const written = pem::armour(pem::private_key_label, pkcs8.bytes().first(*size), text);
    if (!written) {
        return false;
    }
    std::printf("PKCS#8: %zu bytes, %zu characters of PEM, kept secret\n", *size, *written);

    crypto::secret<p256::max_pkcs8_size> read;
    auto const read_size = pem::unarmour(pem::private_key_label,
                                         std::string_view(text.data(), *written), read.writable());
    if (!read_size) {
        return false;
    }
    auto const back = p256::decode_pkcs8(read.bytes().first(*read_size));
    if (!back) {
        return false;
    }
    auto const back_key = back->public_key();
    auto const original_key = key_pair.public_key();
    return back_key && original_key && back_key->uncompressed() == original_key->uncompressed();
}

}  // namespace

int main() {
    // RFC 6979 section A.2.5's key: a published scalar, never a real key.
    std::array<std::uint8_t, 32> const scalar{
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21,
        0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8,
        0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    };
    auto const key_pair = p256::keypair::make(scalar);
    auto const key = key_pair ? key_pair->public_key() : key_pair.error();
    if (!key || !public_key_to_pem(*key) || !key_pair_to_pem(*key_pair)) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("read back: same key\n");
    return 0;
}

// end::program[]
