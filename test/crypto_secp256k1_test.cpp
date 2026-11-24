// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// <webcpp/crypto.hpp> in a program that links libsecp256k1 brings secp256k1's header: its
// branch for WEBCPP_CRYPTO_HAS_SECP256K1 compiles, and the key pair's sign, both of its
// crypto::verify, the low-S functions, the tweaks of tweak.hpp, the formats of formats.hpp, the
// ElligatorSwift of ellswift.hpp, the MuSig2 of musig.hpp and the silent payments of
// silent_payments.hpp are declared through it alone.

#include <webcpp/crypto.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>

#ifndef WEBCPP_CRYPTO_HAS_SECP256K1
#error "the test needs /third_party//secp256k1, which defines WEBCPP_CRYPTO_HAS_SECP256K1"
#endif

namespace secp = webcpp::crypto::curves::secp256k1;

static_assert(std::is_same_v<secp::keypair::backend_type, webcpp::crypto::backends::secp256k1>);
static_assert(webcpp::crypto::can_sign<secp::keypair, webcpp::crypto::schnorr_t,
                                       std::span<std::uint8_t const>>);
static_assert(
    webcpp::crypto::can_verify<webcpp::crypto::schnorr_t, secp::schnorr_signature,
                               std::span<std::uint8_t const>, std::array<std::uint8_t, 32>>);
static_assert(webcpp::crypto::can_verify<webcpp::crypto::ecdsa_sha256_t, secp::ecdsa_signature,
                                         std::span<std::uint8_t const>, secp::public_key>);
static_assert(std::is_function_v<decltype(secp::normalize_low_s<>)>);
static_assert(std::is_function_v<decltype(secp::is_low_s<>)>);
static_assert(std::is_function_v<decltype(secp::secret_key_tweak_add<>)>);
static_assert(std::is_function_v<decltype(secp::public_key_combine<>)>);
static_assert(std::is_function_v<decltype(secp::decode_spki<>)>);
static_assert(std::is_function_v<decltype(secp::decode_pkcs8<>)>);
static_assert(std::is_function_v<decltype(secp::ellswift_decode<>)>);
static_assert(std::is_function_v<decltype(secp::ellswift_xdh<secp::keypair::backend_type>)>);
static_assert(std::is_function_v<decltype(secp::musig::key_aggregate<>)>);
static_assert(std::is_function_v<decltype(secp::musig::partial_sign<secp::keypair::backend_type>)>);
static_assert(std::is_function_v<decltype(secp::silent_payments::create_outputs<>)>);
static_assert(
    std::is_function_v<decltype(secp::silent_payments::scan_outputs<secp::keypair::backend_type>)>);

int main() {
    return 0;
}
