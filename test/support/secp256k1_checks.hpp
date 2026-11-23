// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The checks of a key pair that holds no key (moved from, or refused by a tweak) that the
// secp256k1 tests share.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_CHECKS_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_SECP256K1_CHECKS_HPP

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace webcpp::test {

/**
 * MuSig2's two functions of a signer's key pair answer `invalid_state` for an empty pair: a
 * nonce for it, and a partial signature by it with a nonce of a live pair's.
 *
 * @param key The empty pair.
 * @param live A keyed pair, the one signer of the aggregate key.
 * @param message The 32-byte message of the session.
 */
inline void expect_empty_musig_signer(webcpp::crypto::curves::secp256k1::keypair const& key,
                                      webcpp::crypto::curves::secp256k1::keypair const& live,
                                      std::array<std::uint8_t, 32> const& message) {
    namespace secp = webcpp::crypto::curves::secp256k1;
    auto const live_key = live.public_key();
    if (!BOOST_TEST(live_key.has_value())) {
        return;
    }
    std::array<secp::public_key, 1> const keys{*live_key};
    std::array<std::byte, secp::musig::workspace_size(1)> space{};
    auto const signers_key = secp::musig::key_aggregate(keys, space);
    if (!BOOST_TEST(signers_key.has_value())) {
        return;
    }
    BOOST_TEST(secp::musig::nonce_gen(key, *signers_key).error() ==
               webcpp::crypto::error::invalid_state);
    auto made = secp::musig::nonce_gen(live, *signers_key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    std::array<secp::musig::public_nonce, 1> const nonces{made->public_part};
    auto const nonce_sum = secp::musig::nonce_aggregate(nonces, space);
    if (!BOOST_TEST(nonce_sum.has_value())) {
        return;
    }
    auto const signing_session = secp::musig::nonce_process(*nonce_sum, message, *signers_key);
    if (BOOST_TEST(signing_session.has_value())) {
        BOOST_TEST(secp::musig::partial_sign(key, std::move(made->secret_part), *signers_key,
                                             *signing_session)
                       .error() == webcpp::crypto::error::invalid_state);
    }
}

/**
 * Silent payments' three functions of a key pair answer `invalid_state` for an empty pair: an
 * input of the sender's, on either side, a scan key's label, and a scan by it.
 *
 * @param key The empty pair.
 * @param live A keyed pair, the recipient's scan and spend key and the other input.
 */
inline void expect_empty_silent_payments(webcpp::crypto::curves::secp256k1::keypair const& key,
                                         webcpp::crypto::curves::secp256k1::keypair const& live) {
    namespace secp = webcpp::crypto::curves::secp256k1;
    namespace sp = secp::silent_payments;
    auto const live_key = live.public_key();
    if (!BOOST_TEST(live_key.has_value())) {
        return;
    }
    sp::recipient const address{.scan_key = *live_key, .spend_key = *live_key};
    std::array<sp::recipient, 1> const recipients{address};
    std::array<std::uint8_t, sp::outpoint_size> const outpoint{};
    std::array<secp::keypair const*, 1> const empty_input{&key};
    std::array<secp::keypair const*, 1> const live_input{&live};
    std::array<std::array<std::uint8_t, 32>, 1> outputs{};
    std::array<std::byte, sp::send_workspace_size(1, 1, 1)> send_space{};
    BOOST_TEST(
        sp::create_outputs(recipients, outpoint, empty_input, live_input, outputs, send_space)
            .error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(
        sp::create_outputs(recipients, outpoint, live_input, empty_input, outputs, send_space)
            .error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(sp::create_label(key, 0).error() == webcpp::crypto::error::invalid_state);
    std::array<secp::public_key, 1> const input_keys{*live_key};
    std::array<std::byte, sp::summary_workspace_size(0, 1)> summary_space{};
    auto const summary = sp::make_prevouts_summary(outpoint, {}, input_keys, summary_space);
    if (!BOOST_TEST(summary.has_value())) {
        return;
    }
    std::array<sp::found_output, 1> found{};
    std::array<std::byte, sp::scan_workspace_size(1)> scan_space{};
    BOOST_TEST(sp::scan_outputs(key, *live_key, *summary, outputs, found, scan_space).error() ==
               webcpp::crypto::error::invalid_state);
}

/**
 * Every operation of a key pair that holds no key answers `invalid_state`: the pair is empty,
 * as the source of a move is and as a pair is that a tweak refused.
 *
 * @param key The pair, which the tweak is asked of (it stays empty).
 */
inline void expect_empty_keypair(webcpp::crypto::curves::secp256k1::keypair& key) {
    auto const live =
        webcpp::crypto::curves::secp256k1::keypair::from_secret(std::array<std::uint8_t, 32>{
            1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        });
    std::array<std::uint8_t, 32> const message{};
    std::array<std::uint8_t, 32> const aux{};
    std::array<std::uint8_t, 32> const tweak{};
    BOOST_TEST(key.public_key().error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.secret().error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign(webcpp::crypto::schnorr, message, aux).error() ==
               webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign(webcpp::crypto::schnorr, message).error() ==
               webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign(webcpp::crypto::ecdsa_sha256, message).error() ==
               webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign(webcpp::crypto::ecdsa_sha256, message, aux).error() ==
               webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.sign(webcpp::crypto::ecdsa_sha256_recoverable, message).error() ==
               webcpp::crypto::error::invalid_state);
    BOOST_TEST(key.tweak_xonly(tweak).error() == webcpp::crypto::error::invalid_state);
    BOOST_TEST(webcpp::crypto::curves::secp256k1::ellswift_create(key, aux).error() ==
               webcpp::crypto::error::invalid_state);
    std::array<std::uint8_t, webcpp::crypto::curves::secp256k1::ellswift_size> const noise{};
    BOOST_TEST(webcpp::crypto::curves::secp256k1::ellswift_xdh(
                   key, noise, noise, webcpp::crypto::curves::secp256k1::ellswift_party::initiator)
                   .error() == webcpp::crypto::error::invalid_state);
    std::array<std::uint8_t, webcpp::crypto::curves::secp256k1::max_pkcs8_size> encoding{};
    BOOST_TEST(webcpp::crypto::curves::secp256k1::encode_pkcs8(key, encoding).error() ==
               webcpp::crypto::error::invalid_state);
    if (BOOST_TEST(live.has_value())) {
        auto const peer = *live->public_key();
        BOOST_TEST(key.agree_hashed(peer).error() == webcpp::crypto::error::invalid_state);
        BOOST_TEST(key.agree(peer).error() == webcpp::crypto::error::invalid_state);
        BOOST_TEST(key.agree_point(peer).error() == webcpp::crypto::error::invalid_state);
        expect_empty_musig_signer(key, *live, message);
        expect_empty_silent_payments(key, *live);
    }
}

}  // namespace webcpp::test

#endif
