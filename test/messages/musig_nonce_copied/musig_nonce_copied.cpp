// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A MuSig2 secret nonce passed to partial_sign without std::move: its copy constructor is
// deleted, so a nonce cannot be kept and signed with a second time. A second std::move of the
// same object compiles; partial_sign refuses that one at run time with invalid_state.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

int main() {
    namespace secp = webcpp::crypto::curves::secp256k1;
    namespace musig = webcpp::crypto::curves::secp256k1::musig;
    std::array<std::uint8_t, 32> secret_bytes{};
    secret_bytes.fill(0x11);
    auto const signer = secp::keypair::from_secret(secret_bytes);
    auto const signer_key = signer->public_key();
    std::array<secp::public_key, 1> const keys{*signer_key};
    std::vector<std::byte> space(musig::workspace_size(keys.size()));
    auto const key = musig::key_aggregate(keys, space);
    auto made = musig::nonce_gen(*signer, *key);
    std::array<musig::public_nonce, 1> const nonces{made->public_part};
    auto const sum = musig::nonce_aggregate(nonces, space);
    auto const signing_session = musig::nonce_process(*sum, secret_bytes, *key);
    musig::secret_nonce& kept = made->secret_part;
    // expected-error@+1 {{call to deleted constructor of}}
    auto const part = musig::partial_sign(*signer, kept, *key, *signing_session);
    // clang-format off
    // expected-note@webcpp/crypto/curves/secp256k1/musig.hpp:* {{'secret_nonce' has been explicitly marked deleted here}}
    // clang-format on
    return part ? 0 : 1;
}
