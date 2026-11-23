// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The wallet of musig_wallet.cpp with its two devices apart: every public piece of BIP 327's
// MuSig2 crosses the network as bytes. Each device sends its public nonce, 66 bytes, to a
// coordinator, which holds no secret: it sums the nonces and sends the aggregate nonce, 66
// bytes, back. Each device then signs and sends its partial signature, 32 bytes; the
// coordinator parses each part and checks it with partial_signature_verify before it adds the
// parts, so that a part damaged on the way, or a faulty signer's, is refused by name rather
// than spoiling the signature. The devices' secrets are fixed here, so that the program runs
// the same each time; the nonces are fresh in every run, and nothing random is printed.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace musig = webcpp::crypto::curves::secp256k1::musig;

namespace {

using public_nonce_bytes = std::array<std::uint8_t, musig::public_nonce_size>;
using aggregate_nonce_bytes = std::array<std::uint8_t, musig::aggregate_nonce_size>;
using partial_signature_bytes = std::array<std::uint8_t, musig::partial_signature_size>;

std::array<std::uint8_t, 32> repeated(std::uint8_t value) {
    std::array<std::uint8_t, 32> bytes{};
    bytes.fill(value);
    return bytes;
}

// The wallet's key, which each party aggregates from the two public keys it received: sorted
// (BIP 327's KeySort), it is the same key on every party.
std::optional<musig::aggregate_key> wallet_key_of(secp256k1::public_key const& first,
                                                  secp256k1::public_key const& second) {
    std::array<secp256k1::public_key, 2> keys{first, second};
    std::ranges::sort(keys);
    alignas(std::max_align_t) std::array<std::byte, musig::workspace_size(2)> space{};
    auto aggregated = musig::key_aggregate(keys, space);
    if (!aggregated) {
        return std::nullopt;
    }
    return *aggregated;
}

// The coordinator's checks on what arrived: each part parsed from its 32 bytes, then checked
// against its signer's public nonce and key; the first refusal is returned.
boost::system::result<musig::partial_signature> received_part(
    partial_signature_bytes const& wire, musig::public_nonce const& signer_nonce,
    secp256k1::public_key const& signer_key, musig::aggregate_key const& wallet_key,
    musig::session const& signing_session) {
    auto part = musig::parse_partial_signature(wire);
    if (!part) {
        return part.error();
    }
    auto const checked = musig::partial_signature_verify(*part, signer_nonce, signer_key,
                                                         wallet_key, signing_session);
    if (!checked) {
        return checked.error();
    }
    return part;
}

}  // namespace

int main() {
    // Each device's key pair; each publishes its public key, which every party reads.
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
    auto const wallet_key = wallet_key_of(*phone_key, *laptop_key);
    if (!wallet_key) {
        return 1;
    }

    // The spend both approve: the transaction's 32-byte hash, as a domain library computes it.
    auto const message = repeated(0x5a);

    // Round one, on each device: a nonce for this signature, its public half sent as bytes.
    auto phone_nonce = musig::nonce_gen(*phone, *wallet_key, message);
    auto laptop_nonce = musig::nonce_gen(*laptop, *wallet_key, message);
    if (!phone_nonce || !laptop_nonce) {
        return 1;
    }
    public_nonce_bytes const phone_nonce_wire =
        musig::serialize_public_nonce(phone_nonce->public_part);
    public_nonce_bytes const laptop_nonce_wire =
        musig::serialize_public_nonce(laptop_nonce->public_part);
    std::printf("each device sends its public nonce: %zu bytes\n", phone_nonce_wire.size());

    // The coordinator parses both public nonces, sums them and sends the sum back as bytes.
    auto const phone_nonce_in = musig::parse_public_nonce(phone_nonce_wire);
    auto const laptop_nonce_in = musig::parse_public_nonce(laptop_nonce_wire);
    if (!phone_nonce_in || !laptop_nonce_in) {
        return 1;
    }
    std::array<musig::public_nonce, 2> const nonces{*phone_nonce_in, *laptop_nonce_in};
    alignas(std::max_align_t) std::array<std::byte, musig::workspace_size(2)> space{};
    auto const nonce_sum = musig::nonce_aggregate(nonces, space);
    if (!nonce_sum) {
        return 1;
    }
    aggregate_nonce_bytes const nonce_sum_wire = musig::serialize_aggregate_nonce(*nonce_sum);
    std::printf("the coordinator sends the aggregate nonce: %zu bytes\n", nonce_sum_wire.size());

    // Round two, on each device: the aggregate nonce parsed, the session made (the same on both,
    // so made once here), the part signed (which consumes the secret nonce) and sent as bytes.
    auto const nonce_sum_in = musig::parse_aggregate_nonce(nonce_sum_wire);
    if (!nonce_sum_in) {
        return 1;
    }
    auto const device_session = musig::nonce_process(*nonce_sum_in, message, *wallet_key);
    if (!device_session) {
        return 1;
    }
    auto const phone_part = musig::partial_sign(*phone, std::move(phone_nonce->secret_part),
                                                *wallet_key, *device_session);
    auto const laptop_part = musig::partial_sign(*laptop, std::move(laptop_nonce->secret_part),
                                                 *wallet_key, *device_session);
    if (!phone_part || !laptop_part) {
        return 1;
    }
    partial_signature_bytes const phone_part_wire = musig::serialize_partial_signature(*phone_part);
    partial_signature_bytes const laptop_part_wire =
        musig::serialize_partial_signature(*laptop_part);
    std::printf("each device sends its partial signature: %zu bytes\n", phone_part_wire.size());

    // The coordinator makes the same session from the nonce sum it sent, and checks each part
    // before it adds them.
    auto const signing_session = musig::nonce_process(*nonce_sum, message, *wallet_key);
    if (!signing_session) {
        return 1;
    }
    auto const phone_part_in =
        received_part(phone_part_wire, *phone_nonce_in, *phone_key, *wallet_key, *signing_session);
    auto const laptop_part_in = received_part(laptop_part_wire, *laptop_nonce_in, *laptop_key,
                                              *wallet_key, *signing_session);
    if (!phone_part_in || !laptop_part_in) {
        return 1;
    }
    std::printf("both partial signatures parse and verify\n");

    // The same check refuses the laptop's part with one byte flipped on the way.
    partial_signature_bytes damaged_wire = laptop_part_wire;
    damaged_wire.back() ^= 0x01U;
    auto const damaged =
        received_part(damaged_wire, *laptop_nonce_in, *laptop_key, *wallet_key, *signing_session);
    if (damaged) {
        return 1;
    }
    std::string const reason = damaged.error().message();
    std::printf("a part with one byte flipped is refused: %s\n", reason.c_str());

    // The parts add up to one BIP 340 signature under the wallet's one x-only key.
    std::array<musig::partial_signature, 2> const parts{*phone_part_in, *laptop_part_in};
    auto const signature = musig::partial_signature_aggregate(*signing_session, parts, space);
    if (!signature ||
        !crypto::verify(crypto::schnorr, *signature, message, wallet_key->xonly_public_key())) {
        return 1;
    }
    std::printf("the aggregate signature verifies as one BIP 340 signature: %zu bytes\n",
                signature->size());
    return 0;
}

// end::program[]
