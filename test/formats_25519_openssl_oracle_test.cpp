// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL as an outside oracle of RFC 8410's SPKI and PKCS#8 and of PEM on libsodium (design
// D30): for 200 seeded key pairs per curve, OpenSSL's i2d_PUBKEY and i2d_PrivateKey give the bytes
// that encode_spki and encode_pkcs8 give, its PEM writers give the text that pem::armour gives,
// and its d2i_PUBKEY, d2i_AutoPrivateKey and PEM readers decode ours to the same raw keys. OpenSSL,
// the source-built provider, is linked in this test alone: the formats run on libsodium.

#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/ed25519/formats.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/formats.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace pem = webcpp::crypto::pem;
namespace test = webcpp::test;

namespace {

// The cases per curve, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t seed = 0x52464338343130ULL;

/** Frees an EVP_PKEY. */
struct pkey_free {
    void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
};

/** Frees a BIO. */
struct bio_free {
    void operator()(BIO* bio) const noexcept { BIO_free(bio); }
};

using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using bio_ptr = std::unique_ptr<BIO, bio_free>;

/** 32 bytes of the seeded generator. */
std::array<std::uint8_t, 32> drawn(std::mt19937_64& generator) {
    std::array<std::uint8_t, 32> bytes{};
    for (auto& b : bytes) {
        b = static_cast<std::uint8_t>(generator() & 0xffU);
    }
    return bytes;
}

/** OpenSSL's DER of a key through i2d_PUBKEY or i2d_PrivateKey. */
template <class Encode>
std::vector<std::uint8_t> der_by(EVP_PKEY* key, Encode encode) {
    int const size = encode(key, nullptr);
    if (size <= 0) {
        return {};
    }
    std::vector<std::uint8_t> der(static_cast<std::size_t>(size));
    unsigned char* at = der.data();
    if (encode(key, &at) != size) {
        return {};
    }
    return der;
}

/** OpenSSL's PEM text of a key through a PEM writer. */
template <class Write>
std::string pem_by(EVP_PKEY* key, Write write) {
    bio_ptr const bio{BIO_new(BIO_s_mem())};
    if (!bio || write(bio.get(), key) != 1) {
        return {};
    }
    char* data = nullptr;
    long const size = BIO_get_mem_data(bio.get(), &data);
    return size > 0 ? std::string(data, static_cast<std::size_t>(size)) : std::string{};
}

/** A BIO that reads text. */
bio_ptr reading(std::string_view text) {
    return bio_ptr{BIO_new_mem_buf(text.data(), static_cast<int>(text.size()))};
}

/** The raw public key OpenSSL reads from an SPKI. */
std::vector<std::uint8_t> raw_public_of_spki(std::span<std::uint8_t const> spki) {
    unsigned char const* at = spki.data();
    pkey_ptr const key{d2i_PUBKEY(nullptr, &at, static_cast<long>(spki.size()))};
    std::vector<std::uint8_t> raw(32);
    std::size_t size = raw.size();
    if (!key || at != spki.data() + spki.size() ||
        EVP_PKEY_get_raw_public_key(key.get(), raw.data(), &size) != 1 || size != 32) {
        return {};
    }
    return raw;
}

/** The raw private key OpenSSL reads from a PKCS#8. */
std::vector<std::uint8_t> raw_private_of_pkcs8(std::span<std::uint8_t const> pkcs8) {
    unsigned char const* at = pkcs8.data();
    pkey_ptr const key{d2i_AutoPrivateKey(nullptr, &at, static_cast<long>(pkcs8.size()))};
    std::vector<std::uint8_t> raw(32);
    std::size_t size = raw.size();
    if (!key || at != pkcs8.data() + pkcs8.size() ||
        EVP_PKEY_get_raw_private_key(key.get(), raw.data(), &size) != 1 || size != 32) {
        return {};
    }
    return raw;
}

/** pem::armour's text of DER. */
std::string armoured(std::string_view label, std::span<std::uint8_t const> der) {
    std::string text(pem::armoured_size(label.size(), der.size()), '\0');
    auto const written = pem::armour(label, der, text);
    BOOST_TEST(written.has_value());
    return written ? text : std::string{};
}

/** The bytes of a key, as a vector a test compares. */
std::vector<std::uint8_t> bytes_of(std::span<std::uint8_t const> key) {
    return {key.begin(), key.end()};
}

/**
 * One key of a curve: OpenSSL's encodings of its raw keys against ours, both ways. `type` is
 * EVP_PKEY_ED25519 or EVP_PKEY_X25519; spki and pkcs8 are ours.
 */
bool agree(int type, std::span<std::uint8_t const, 32> secret, std::span<std::uint8_t const> spki,
           std::span<std::uint8_t const> pkcs8) {
    pkey_ptr const key{EVP_PKEY_new_raw_private_key(type, nullptr, secret.data(), secret.size())};
    if (!BOOST_TEST(key)) {
        return false;
    }
    bool const same_spki = BOOST_TEST(der_by(key.get(), i2d_PUBKEY) == bytes_of(spki));
    bool const same_pkcs8 = BOOST_TEST(der_by(key.get(), i2d_PrivateKey) == bytes_of(pkcs8));
    bool const same_public_pem = BOOST_TEST(pem_by(key.get(), PEM_write_bio_PUBKEY) ==
                                            armoured(pem::public_key_label, spki));
    auto const write_private = [](BIO* bio, EVP_PKEY* k) {
        return PEM_write_bio_PrivateKey(bio, k, nullptr, nullptr, 0, nullptr, nullptr);
    };
    bool const same_private_pem =
        BOOST_TEST(pem_by(key.get(), write_private) == armoured(pem::private_key_label, pkcs8));

    // OpenSSL reads ours, as DER and as PEM, to the same raw keys.
    std::vector<std::uint8_t> raw_public(32);
    std::size_t size = raw_public.size();
    BOOST_TEST(EVP_PKEY_get_raw_public_key(key.get(), raw_public.data(), &size) == 1);
    bool const read_spki = BOOST_TEST(raw_public_of_spki(spki) == raw_public);
    bool const read_pkcs8 = BOOST_TEST(raw_private_of_pkcs8(pkcs8) == bytes_of(secret));
    auto const public_text = armoured(pem::public_key_label, spki);
    auto const public_bio = reading(public_text);
    pkey_ptr const from_public_pem{
        PEM_read_bio_PUBKEY(public_bio.get(), nullptr, nullptr, nullptr)};
    auto const private_text = armoured(pem::private_key_label, pkcs8);
    auto const private_bio = reading(private_text);
    pkey_ptr const from_private_pem{
        PEM_read_bio_PrivateKey(private_bio.get(), nullptr, nullptr, nullptr)};
    bool const read_pem = BOOST_TEST(from_public_pem && from_private_pem &&
                                     EVP_PKEY_eq(from_public_pem.get(), key.get()) == 1 &&
                                     EVP_PKEY_eq(from_private_pem.get(), key.get()) == 1);
    return same_spki && same_pkcs8 && same_public_pem && same_private_pem && read_spki &&
           read_pkcs8 && read_pem;
}

void ed25519_against_openssl(std::mt19937_64& generator) {
    for (std::size_t round = 0; round < cases; ++round) {
        auto const seed_bytes = drawn(generator);
        auto const pair = ed25519::keypair::make(seed_bytes);
        boost::system::result<std::array<std::uint8_t, 32>> const public_key =
            pair ? pair->public_key() : crypto::error::backend_failure;
        if (!BOOST_TEST(public_key.has_value())) {
            std::fprintf(stderr, "Ed25519 key pair not made: seed %s\n",
                         test::to_hex(seed_bytes).c_str());
            continue;
        }
        std::array<std::uint8_t, ed25519::max_spki_size> spki{};
        std::array<std::uint8_t, ed25519::max_pkcs8_size> pkcs8{};
        BOOST_TEST(ed25519::encode_spki(*public_key, spki).has_value());
        BOOST_TEST(ed25519::encode_pkcs8(*pair, pkcs8).has_value());
        if (!agree(EVP_PKEY_ED25519, seed_bytes, spki, pkcs8)) {
            std::fprintf(stderr, "Ed25519 disagrees with OpenSSL: seed %s\n",
                         test::to_hex(seed_bytes).c_str());
        }
    }
}

void x25519_against_openssl(std::mt19937_64& generator) {
    for (std::size_t round = 0; round < cases; ++round) {
        auto const secret_key = drawn(generator);
        auto const public_key = x25519::public_key(secret_key);
        BOOST_TEST(public_key.has_value());
        if (!public_key) {
            continue;
        }
        std::array<std::uint8_t, x25519::max_spki_size> spki{};
        std::array<std::uint8_t, x25519::max_pkcs8_size> pkcs8{};
        BOOST_TEST(x25519::encode_spki(*public_key, spki).has_value());
        BOOST_TEST(x25519::encode_pkcs8(secret_key, pkcs8).has_value());
        if (!agree(EVP_PKEY_X25519, secret_key, spki, pkcs8)) {
            std::fprintf(stderr, "X25519 disagrees with OpenSSL: secret key %s\n",
                         test::to_hex(secret_key).c_str());
        }
    }
}

}  // namespace

int main() {
    std::mt19937_64 generator(seed);
    ed25519_against_openssl(generator);
    x25519_against_openssl(generator);
    std::printf("formats against OpenSSL: %zu cases per curve\n", cases);
    return test::exit_status(boost::report_errors());
}
