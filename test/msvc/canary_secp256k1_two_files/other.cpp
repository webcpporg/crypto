// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The second translation unit of canary_secp256k1_two_files: it names the small tables'
// configuration, so its detect_mismatch value differs from app.cpp's. It also defines the canary
// that configuration names, so that the symbol this unit reads is found: the link fails by the
// third layer alone (the pragma, LNK2038), and not by the second (a missing symbol, LNK2001),
// which would fail the link with the pragma removed as well.
#define WEBCPP_CRYPTO_SECP256K1_CANARY_CONFIGURATION w2c2x5

#include <webcpp/crypto/curves/secp256k1.hpp>

#include <array>
#include <cstdint>

// The canary of the configuration above, which the large tables' archive does not define. The
// header declared it, so this definition has external linkage.
extern "C" const char WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY = 0;

bool sign_other() {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(0x42);
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    auto key = webcpp::crypto::curves::secp256k1::keypair::make(secret);
    return key && key->sign_schnorr(message, aux);
}
