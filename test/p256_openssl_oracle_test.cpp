// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// OpenSSL, through its C API, as an outside oracle of P-256 on BearSSL, natively and on wasip2
// and wasip3 (OpenSSL is linked in this test alone). From a printed seed, 200 cases of each:
//
// - Signatures: a random scalar made into our key pair and into OpenSSL's EVP_PKEY (from the
//   scalar, its public point d * G computed by OpenSSL's EC_POINT_mul, then OSSL_PARAM_BLD and
//   EVP_PKEY_fromdata), OpenSSL's point equal to ours; a random 32-byte digest; OpenSSL signs it
//   with RFC 6979's nonce over SHA-256 (the parameters `nonce-type` 1 and `digest` "SHA256",
//   OpenSSL 3.2 and later), and its DER signature through from_der equals sign_ecdsa's bytes;
//   OpenSSL verifies to_der of ours, and verify_ecdsa accepts OpenSSL's.
// - ECDH: two random key pairs; EVP_PKEY_derive of the first with the second's public key equals
//   ecdh_x.
// - Formats: OpenSSL's i2d_PUBKEY and its PrivateKeyInfo (an OSSL_ENCODER, DER) decode with
//   decode_spki and decode_pkcs8 and encode again to the same bytes; encode_spki's and
//   encode_pkcs8's bytes load in OpenSSL (d2i_PUBKEY, d2i_AutoPrivateKey) to the same key, its
//   public point by EVP_PKEY_eq and its scalar compared on its own, since EVP_PKEY_eq compares the
//   public components alone.
//
// A case agrees when every check of it holds. The program prints `oracle ok <n>`, the cases that
// agree, and passes when n is 600 and OpenSSL's error queue is empty at the end.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <random>
#include <span>
#include <vector>

namespace p256 = webcpp::crypto::curves::p256;
namespace test = webcpp::test;

namespace {

// The cases per group, and the seed that makes a failure reproducible.
constexpr std::size_t cases = 200;
constexpr std::uint64_t generator_seed = 0x5032353673736cULL;

using bytes = std::vector<std::uint8_t>;
using scalar_bytes = std::array<std::uint8_t, p256::secret_key_size>;

/** Frees an EVP_PKEY. */
struct pkey_free {
    void operator()(EVP_PKEY* key) const noexcept { EVP_PKEY_free(key); }
};

/** Frees an EVP_PKEY_CTX. */
struct pkey_ctx_free {
    void operator()(EVP_PKEY_CTX* context) const noexcept { EVP_PKEY_CTX_free(context); }
};

/** Frees a BIGNUM that held a secret, clearing it. */
struct bn_free {
    void operator()(BIGNUM* number) const noexcept { BN_clear_free(number); }
};

/** Frees an OSSL_PARAM_BLD. */
struct param_bld_free {
    void operator()(OSSL_PARAM_BLD* builder) const noexcept { OSSL_PARAM_BLD_free(builder); }
};

/** Frees an OSSL_PARAM array that a builder made. */
struct params_free {
    void operator()(OSSL_PARAM* params) const noexcept { OSSL_PARAM_free(params); }
};

/** Frees an OSSL_ENCODER_CTX. */
struct encoder_free {
    void operator()(OSSL_ENCODER_CTX* context) const noexcept { OSSL_ENCODER_CTX_free(context); }
};

/** Frees what OpenSSL allocated with OPENSSL_malloc. */
struct openssl_free {
    void operator()(unsigned char* data) const noexcept { OPENSSL_free(data); }
};

// OpenSSL's selection of a key's private and public parts, for fromdata and the encoder.
// NOLINTNEXTLINE(bugprone-signed-bitwise): OpenSSL's selection macro ORs signed flags
constexpr int keypair_selection = EVP_PKEY_KEYPAIR;

using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;
using pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free>;

/** A scalar our key pair takes: 32 bytes of the seeded generator, drawn again until 0 < d < n. */
scalar_bytes drawn_scalar(std::mt19937_64& generator) {
    for (;;) {
        scalar_bytes scalar{};
        for (auto& b : scalar) {
            b = static_cast<std::uint8_t>(generator() & 0xffU);
        }
        if (p256::keypair::make(scalar)) {
            return scalar;
        }
    }
}

/** 32 bytes of the seeded generator: a digest. */
std::array<std::uint8_t, p256::digest_size> drawn_digest(std::mt19937_64& generator) {
    std::array<std::uint8_t, p256::digest_size> digest{};
    for (auto& b : digest) {
        b = static_cast<std::uint8_t>(generator() & 0xffU);
    }
    return digest;
}

/** Frees an EC_GROUP. */
struct group_free {
    void operator()(EC_GROUP* group) const noexcept { EC_GROUP_free(group); }
};

/** Frees an EC_POINT. */
struct point_free {
    void operator()(EC_POINT* point) const noexcept { EC_POINT_free(point); }
};

/**
 * OpenSSL's P-256 key from a scalar: OpenSSL computes its public point d * G itself (EC_POINT_mul,
 * since EVP_PKEY_fromdata does not compute it from the private key), and the key takes both.
 */
pkey_ptr openssl_key(std::span<std::uint8_t const, p256::secret_key_size> scalar) {
    std::unique_ptr<BIGNUM, bn_free> const number{
        BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr)};
    std::unique_ptr<EC_GROUP, group_free> const group{
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)};
    std::unique_ptr<EC_POINT, point_free> const point{group ? EC_POINT_new(group.get()) : nullptr};
    std::array<unsigned char, p256::public_key_size> encoded{};
    if (!number || !point ||
        EC_POINT_mul(group.get(), point.get(), number.get(), nullptr, nullptr, nullptr) != 1 ||
        EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, encoded.data(),
                           encoded.size(), nullptr) != encoded.size()) {
        return {};
    }
    std::unique_ptr<OSSL_PARAM_BLD, param_bld_free> const builder{OSSL_PARAM_BLD_new()};
    if (!builder ||
        OSSL_PARAM_BLD_push_utf8_string(builder.get(), OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) !=
            1 ||
        OSSL_PARAM_BLD_push_BN(builder.get(), OSSL_PKEY_PARAM_PRIV_KEY, number.get()) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(builder.get(), OSSL_PKEY_PARAM_PUB_KEY, encoded.data(),
                                         encoded.size()) != 1) {
        return {};
    }
    std::unique_ptr<OSSL_PARAM, params_free> const params{OSSL_PARAM_BLD_to_param(builder.get())};
    pkey_ctx_ptr const context{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    EVP_PKEY* key = nullptr;
    if (!params || !context || EVP_PKEY_fromdata_init(context.get()) != 1 ||
        EVP_PKEY_fromdata(context.get(), &key, keypair_selection, params.get()) != 1) {
        return {};
    }
    return pkey_ptr{key};
}

/** OpenSSL's uncompressed public point of a key. */
bytes openssl_point(EVP_PKEY const* key) {
    bytes point(p256::public_key_size);
    std::size_t size = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size(),
                                        &size) != 1 ||
        size != point.size()) {
        return {};
    }
    return point;
}

/** OpenSSL's DER signature of a digest, its nonce RFC 6979's over SHA-256. */
bytes openssl_sign(EVP_PKEY* key, std::span<std::uint8_t const, p256::digest_size> digest) {
    pkey_ctx_ptr const context{EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)};
    unsigned int nonce_type = 1;
    std::array<char, 7> digest_name{"SHA256"};
    std::array<OSSL_PARAM, 3> const params{
        OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
        OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, digest_name.data(), 0),
        OSSL_PARAM_construct_end(),
    };
    std::size_t size = 0;
    if (!context || EVP_PKEY_sign_init_ex(context.get(), params.data()) != 1 ||
        EVP_PKEY_sign(context.get(), nullptr, &size, digest.data(), digest.size()) != 1) {
        return {};
    }
    bytes der(size);
    if (EVP_PKEY_sign(context.get(), der.data(), &size, digest.data(), digest.size()) != 1) {
        return {};
    }
    der.resize(size);
    return der;
}

/** Whether OpenSSL verifies a DER signature of a digest. */
bool openssl_verifies(EVP_PKEY* key, std::span<std::uint8_t const> der,
                      std::span<std::uint8_t const, p256::digest_size> digest) {
    pkey_ctx_ptr const context{EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)};
    return context && EVP_PKEY_verify_init(context.get()) == 1 &&
           EVP_PKEY_verify(context.get(), der.data(), der.size(), digest.data(), digest.size()) ==
               1;
}

/** OpenSSL's ECDH of a key with a peer's: the shared x. */
bytes openssl_derive(EVP_PKEY* key, EVP_PKEY* peer) {
    pkey_ctx_ptr const context{EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)};
    std::size_t size = 0;
    if (!context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer) != 1 ||
        EVP_PKEY_derive(context.get(), nullptr, &size) != 1) {
        return {};
    }
    bytes shared(size);
    if (EVP_PKEY_derive(context.get(), shared.data(), &size) != 1) {
        return {};
    }
    shared.resize(size);
    return shared;
}

/** OpenSSL's SPKI of a key, i2d_PUBKEY. */
bytes openssl_spki(EVP_PKEY const* key) {
    int const size = i2d_PUBKEY(key, nullptr);
    if (size <= 0) {
        return {};
    }
    bytes der(static_cast<std::size_t>(size));
    unsigned char* at = der.data();
    if (i2d_PUBKEY(key, &at) != size) {
        return {};
    }
    return der;
}

/** OpenSSL's PKCS#8 of a key, its encoder's DER PrivateKeyInfo. */
bytes openssl_pkcs8(EVP_PKEY const* key) {
    std::unique_ptr<OSSL_ENCODER_CTX, encoder_free> const encoder{
        OSSL_ENCODER_CTX_new_for_pkey(key, keypair_selection, "DER", "PrivateKeyInfo", nullptr)};
    unsigned char* data = nullptr;
    std::size_t size = 0;
    if (!encoder || OSSL_ENCODER_CTX_get_num_encoders(encoder.get()) == 0 ||
        OSSL_ENCODER_to_data(encoder.get(), &data, &size) != 1) {
        return {};
    }
    std::unique_ptr<unsigned char, openssl_free> const owned{data};
    return {data, data + size};
}

/** The key OpenSSL reads from an SPKI, the whole input consumed. */
pkey_ptr openssl_read_spki(std::span<std::uint8_t const> spki) {
    unsigned char const* at = spki.data();
    pkey_ptr key{d2i_PUBKEY(nullptr, &at, static_cast<long>(spki.size()))};
    return at == spki.data() + spki.size() ? std::move(key) : pkey_ptr{};
}

/** The key OpenSSL reads from a PKCS#8, the whole input consumed. */
pkey_ptr openssl_read_pkcs8(std::span<std::uint8_t const> pkcs8) {
    unsigned char const* at = pkcs8.data();
    pkey_ptr key{d2i_AutoPrivateKey(nullptr, &at, static_cast<long>(pkcs8.size()))};
    return at == pkcs8.data() + pkcs8.size() ? std::move(key) : pkey_ptr{};
}

/**
 * The scalar OpenSSL holds in a key, as 32 big-endian bytes in a `secret`: `EVP_PKEY_eq` compares
 * public components alone, so the scalar a PKCS#8 loads is compared on its own. OpenSSL's copy is
 * a BIGNUM freed with BN_clear_free.
 */
webcpp::crypto::secret<p256::secret_key_size> openssl_scalar(EVP_PKEY const* key) {
    webcpp::crypto::secret<p256::secret_key_size> scalar;
    BIGNUM* number = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &number) != 1) {
        return scalar;
    }
    std::unique_ptr<BIGNUM, bn_free> const owned{number};
    auto const out = scalar.writable();
    if (BN_bn2binpad(owned.get(), out.data(), static_cast<int>(out.size())) !=
        static_cast<int>(out.size())) {
        std::ranges::fill(out, std::uint8_t{0});
    }
    return scalar;
}

template <std::size_t N>
bytes bytes_of(std::array<std::uint8_t, N> const& array) {
    return {array.begin(), array.end()};
}

/** One signature case: true when OpenSSL agrees with it. */
bool signature_case(std::mt19937_64& generator, std::size_t index) {
    auto const scalar = drawn_scalar(generator);
    auto const digest = drawn_digest(generator);
    auto const pair = p256::keypair::make(scalar);
    auto const public_key = pair ? pair->public_key() : webcpp::crypto::error::backend_failure;
    auto const ours = pair ? pair->sign_ecdsa(digest) : webcpp::crypto::error::backend_failure;
    pkey_ptr const key = openssl_key(scalar);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(ours.has_value()) || !BOOST_TEST(key)) {
        return false;
    }
    bool const same_point =
        BOOST_TEST(openssl_point(key.get()) == bytes_of(public_key->uncompressed()));
    bytes const theirs_der = openssl_sign(key.get(), digest);
    auto const theirs = p256::from_der(theirs_der);
    bool const same_signature = BOOST_TEST(theirs.has_value()) && BOOST_TEST(*theirs == *ours);
    std::array<std::uint8_t, p256::max_der_size> der{};
    auto const der_size = p256::to_der(*ours, der);
    bool const openssl_verifies_ours =
        BOOST_TEST(der_size.has_value()) &&
        BOOST_TEST(openssl_verifies(key.get(), std::span(der).first(*der_size), digest));
    bool const we_verify_theirs =
        BOOST_TEST(theirs && p256::verify_ecdsa(*theirs, digest, *public_key).has_value());
    bool const agrees = same_point && same_signature && openssl_verifies_ours && we_verify_theirs;
    if (!agrees) {
        static_cast<void>(std::fprintf(stderr,
                                       "signature case %zu: OpenSSL disagrees: scalar %s, digest "
                                       "%s\n",
                                       index, test::to_hex(scalar).c_str(),
                                       test::to_hex(digest).c_str()));
    }
    return agrees;
}

/** One ECDH case: true when OpenSSL agrees with it. */
bool ecdh_case(std::mt19937_64& generator, std::size_t index) {
    auto const scalar = drawn_scalar(generator);
    auto const peer_scalar = drawn_scalar(generator);
    auto const pair = p256::keypair::make(scalar);
    auto const peer = p256::keypair::make(peer_scalar);
    auto const peer_public_key = peer ? peer->public_key() : webcpp::crypto::error::backend_failure;
    auto const shared = pair && peer_public_key ? pair->ecdh_x(*peer_public_key)
                                                : webcpp::crypto::error::backend_failure;
    pkey_ptr const key = openssl_key(scalar);
    pkey_ptr const peer_key = openssl_key(peer_scalar);
    if (!BOOST_TEST(shared.has_value()) || !BOOST_TEST(key) || !BOOST_TEST(peer_key)) {
        return false;
    }
    auto const ours = shared->bytes();
    bool const agrees =
        BOOST_TEST(openssl_derive(key.get(), peer_key.get()) == bytes(ours.begin(), ours.end()));
    if (!agrees) {
        static_cast<void>(std::fprintf(stderr, "ECDH case %zu: OpenSSL disagrees: scalars %s, %s\n",
                                       index, test::to_hex(scalar).c_str(),
                                       test::to_hex(peer_scalar).c_str()));
    }
    return agrees;
}

/** One formats case: true when OpenSSL agrees with it. */
bool formats_case(std::mt19937_64& generator, std::size_t index) {
    auto const scalar = drawn_scalar(generator);
    auto const pair = p256::keypair::make(scalar);
    auto const public_key = pair ? pair->public_key() : webcpp::crypto::error::backend_failure;
    pkey_ptr const key = openssl_key(scalar);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(key)) {
        return false;
    }
    std::array<std::uint8_t, p256::max_spki_size> spki{};
    std::array<std::uint8_t, p256::max_pkcs8_size> pkcs8{};
    BOOST_TEST(p256::encode_spki(*public_key, spki).has_value());
    BOOST_TEST(p256::encode_pkcs8(*pair, pkcs8).has_value());

    // OpenSSL's bytes decode, and encode again to the same bytes.
    bytes const their_spki = openssl_spki(key.get());
    bytes const their_pkcs8 = openssl_pkcs8(key.get());
    auto const decoded_key = p256::decode_spki(their_spki);
    auto const decoded_pair = p256::decode_pkcs8(their_pkcs8);
    std::array<std::uint8_t, p256::max_spki_size> spki_again{};
    std::array<std::uint8_t, p256::max_pkcs8_size> pkcs8_again{};
    bool const spki_round_trip =
        BOOST_TEST(decoded_key.has_value()) &&
        BOOST_TEST(p256::encode_spki(*decoded_key, spki_again).has_value()) &&
        BOOST_TEST(bytes_of(spki_again) == their_spki);
    bool const pkcs8_round_trip =
        BOOST_TEST(decoded_pair.has_value()) &&
        BOOST_TEST(p256::encode_pkcs8(*decoded_pair, pkcs8_again).has_value()) &&
        BOOST_TEST(bytes_of(pkcs8_again) == their_pkcs8);

    // Ours load in OpenSSL to the same key.
    pkey_ptr const from_spki = openssl_read_spki(spki);
    pkey_ptr const from_pkcs8 = openssl_read_pkcs8(pkcs8);
    auto const loaded_scalar = from_pkcs8 ? openssl_scalar(from_pkcs8.get())
                                          : webcpp::crypto::secret<p256::secret_key_size>{};
    bool const openssl_reads_ours =
        BOOST_TEST(from_spki && EVP_PKEY_eq(from_spki.get(), key.get()) == 1) &&
        BOOST_TEST(from_pkcs8 && EVP_PKEY_eq(from_pkcs8.get(), key.get()) == 1) &&
        BOOST_TEST(webcpp::crypto::equal(loaded_scalar.bytes(), scalar));
    bool const agrees = spki_round_trip && pkcs8_round_trip && openssl_reads_ours;
    if (!agrees) {
        static_cast<void>(std::fprintf(stderr, "formats case %zu: OpenSSL disagrees: scalar %s\n",
                                       index, test::to_hex(scalar).c_str()));
    }
    return agrees;
}

}  // namespace

int main() {
    std::printf("p256 openssl oracle: seed %llu, %s\n",
                static_cast<unsigned long long>(generator_seed), OpenSSL_version(OPENSSL_VERSION));
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(generator_seed);
    std::size_t agreed = 0;
    for (std::size_t i = 0; i < cases; ++i) {
        agreed += signature_case(generator, i) ? 1 : 0;
    }
    for (std::size_t i = 0; i < cases; ++i) {
        agreed += ecdh_case(generator, i) ? 1 : 0;
    }
    for (std::size_t i = 0; i < cases; ++i) {
        agreed += formats_case(generator, i) ? 1 : 0;
    }
    std::printf("oracle ok %zu\n", agreed);
    BOOST_TEST_EQ(agreed, 3 * cases);
    // OpenSSL's error queue holds nothing of this program's calls.
    BOOST_TEST_EQ(ERR_peek_error(), 0UL);
    return test::exit_status(boost::report_errors());
}
