// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The wallet of musig_wallet.cpp receiving to a Taproot output (BIP 341) with a key path only:
// the two signers' aggregate key is the internal key, and the output key on the chain is that
// key tweaked by its TapTweak tagged hash. The tweak is applied to the aggregate key with
// tweak_xonly_add before any nonce is made, since the session and the partial signatures need
// the key as tweaked, and nonce_gen mixes in the key it is given (BIP 327's NonceGen takes it
// only as an optional input); then the signers run MuSig2's two rounds as before, and the
// signature verifies under the output key and not under the internal one. The tweak's hash is
// the protocol's, which a domain library computes; it is shown here with webcpp::hash's SHA-256.
// The devices' secrets are fixed here, so that the program runs the same each time; the nonces
// are fresh in every run, and nothing random is printed.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace musig = webcpp::crypto::curves::secp256k1::musig;

namespace {

std::array<std::uint8_t, 32> repeated(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(value);
    return bytes;
}

// BIP 340's tagged hash, SHA-256(SHA-256(tag) || SHA-256(tag) || data), with which BIP 341
// derives the tweak: the tag keeps a hash made for one purpose from being valid for another.
std::array<std::uint8_t, 32> tagged_hash(std::string_view tag, std::span<std::uint8_t const> data) {
    webcpp::hash::sha2_256 tag_hash;
    tag_hash.update(tag.data(), tag.size());
    auto const prefix = tag_hash.result();

    webcpp::hash::sha2_256 hash;
    hash.update(prefix.data(), prefix.size());
    hash.update(prefix.data(), prefix.size());
    hash.update(data.data(), data.size());
    auto const digest = hash.result();
    std::array<std::uint8_t, 32> out{};
    std::ranges::copy(digest, out.begin());
    return out;
}

}  // namespace

int main() {
    // Each device's key pair; each sends the other its public key.
    auto const phone = secp256k1::keypair::from_secret(repeated(0x11));
    auto const laptop = secp256k1::keypair::from_secret(repeated(0x22));
    if (!phone || !laptop) {
        return 1;
    }
    auto const phone_key = phone->public_key();
    auto const laptop_key = laptop->public_key();
    if (!phone_key || !laptop_key) {
        return 1;
    }

    // The keys sorted and aggregated: the output's internal key.
    std::array<secp256k1::public_key, 2> keys{*phone_key, *laptop_key};
    std::ranges::sort(keys);
    alignas(std::max_align_t) std::array<std::byte, musig::workspace_size(2)> space{};
    auto wallet_key = musig::key_aggregate(keys, space);
    if (!wallet_key) {
        return 1;
    }
    auto const internal_key = wallet_key->xonly_public_key();
    std::printf("internal key aggregated from %zu signers\n", keys.size());

    // BIP 341's tweak of a key-path-only output, the tagged hash of the internal key, applied
    // as an x-only tweak before any nonce is made: the output key is the key on the chain.
    auto const tweak = tagged_hash("TapTweak", internal_key);
    if (!wallet_key->tweak_xonly_add(tweak)) {
        return 1;
    }
    auto const output_key = wallet_key->xonly_public_key();
    if (output_key == internal_key) {
        return 1;
    }
    std::printf("output key tweaked with TapTweak, a key other than the internal key\n");

    // The spend both approve: the transaction's 32-byte hash (BIP 341's signature message), as
    // a domain library computes it.
    auto const message = repeated(0x5a);

    // MuSig2's two rounds under the tweaked key: a nonce each, the session, a part each.
    auto phone_nonce = musig::nonce_gen(*phone, *wallet_key, message);
    auto laptop_nonce = musig::nonce_gen(*laptop, *wallet_key, message);
    if (!phone_nonce || !laptop_nonce) {
        return 1;
    }
    std::array<musig::public_nonce, 2> const nonces{
        phone_nonce->public_part,
        laptop_nonce->public_part,
    };
    auto const nonce_sum = musig::nonce_aggregate(nonces, space);
    if (!nonce_sum) {
        return 1;
    }
    auto const signing_session = musig::nonce_process(*nonce_sum, message, *wallet_key);
    if (!signing_session) {
        return 1;
    }
    auto const phone_part = musig::partial_sign(*phone, std::move(phone_nonce->secret_part),
                                                *wallet_key, *signing_session);
    auto const laptop_part = musig::partial_sign(*laptop, std::move(laptop_nonce->secret_part),
                                                 *wallet_key, *signing_session);
    if (!phone_part || !laptop_part ||
        !musig::partial_signature_verify(*phone_part, nonces[0], *phone_key, *wallet_key,
                                         *signing_session) ||
        !musig::partial_signature_verify(*laptop_part, nonces[1], *laptop_key, *wallet_key,
                                         *signing_session)) {
        return 1;
    }
    std::printf("both partial signatures verify\n");

    // One BIP 340 signature: valid under the output key, which spends the output by its key
    // path, and not under the internal key.
    std::array<musig::partial_signature, 2> const parts{*phone_part, *laptop_part};
    auto const signature = musig::partial_signature_aggregate(*signing_session, parts, space);
    if (!signature || !crypto::verify(crypto::schnorr, *signature, message, output_key)) {
        return 1;
    }
    std::printf("the signature verifies under the output key\n");
    auto const under_internal = crypto::verify(crypto::schnorr, *signature, message, internal_key);
    if (under_internal) {
        return 1;
    }
    std::string const reason = under_internal.error().message();
    std::printf("under the internal key it is refused: %s\n", reason.c_str());
    return 0;
}

// end::program[]
