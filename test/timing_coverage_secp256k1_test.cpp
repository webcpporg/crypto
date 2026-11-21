// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs libsecp256k1's code enters its own detail::timing_guard and
// leaves the thread's DIT as it found it, on every target, also where DIT does not apply, each
// with valid input and, where it has one, with input refused before the backend
// (support/timing_coverage.hpp). One section per header. With exceptions, a memory resource that
// throws in basic_keypair::make and decode_pkcs8 unwinds through the guard, which leaves DIT clear
// from clear and set from set.
// A check fails, naming itself, when its call enters no guard or when the first guard it enters is
// not the one of the function it names (support/timing_seam.hpp), so that a function that forgot
// its own guard fails although it calls another guarded function.
//
// What it covers, by family; a family libsecp256k1 gains adds its line and its checks:
// - secp256k1, curves/secp256k1.hpp: public_key's operator== and operator<=>; basic_keypair:
//   make, xonly_public_key, public_key, public_key_uncompressed, sign_schnorr, both sign_ecdsa,
//   sign_recoverable, ecdh, ecdh_x, ecdh_point, tweak_xonly; the free parse_public_key,
//   serialize_public_key, recover, verify_schnorr, verify_ecdsa, to_der, from_der,
//   normalize_ecdsa, tweak_xonly. Its formats: encode_spki, decode_spki, encode_pkcs8,
//   decode_pkcs8. Its tweaks: seckey_tweak_add, seckey_tweak_mul, seckey_negate,
//   pubkey_tweak_add, pubkey_tweak_mul, pubkey_negate, pubkey_combine.
// - ElligatorSwift: ellswift_encode, ellswift_decode, ellswift_create, ellswift_xdh.
// - MuSig2, a whole round of two signers: aggregate_key's xonly_public_key, full_public_key,
//   tweak_add, tweak_xonly_add; the free key_aggregate, nonce_gen, nonce_aggregate,
//   nonce_process, partial_sign, partial_signature_verify, partial_signature_aggregate, and the
//   parse and serialize of the public nonce, the aggregate nonce and the partial signature.
// - BIP 352 silent payments, a payment created and scanned: create_label,
//   create_labeled_spend_key, create_outputs, make_prevouts_summary, scan_outputs.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/curves/secp256k1/formats.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#include <webcpp/crypto/curves/secp256k1/tweak.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
#include <new>
#endif

namespace {

namespace crypto = webcpp::crypto;
namespace secp = crypto::curves::secp256k1;
namespace musig = secp::musig;
namespace sp = secp::silent_payments;
using webcpp::test::covered;

/** 32 bytes. */
using bytes32 = std::array<std::uint8_t, 32>;

/** A secret key of 32 bytes `fill`, below the group order for any `fill` but 0xff. */
bytes32 secret_bytes(std::uint8_t fill) {
    bytes32 secret_key{};
    secret_key.fill(fill);
    return secret_key;
}

/** The key pair of the secret key of 32 bytes `fill`, made outside a check. */
secp::keypair keypair_of(std::uint8_t fill) {
    auto made = secp::keypair::make(secret_bytes(fill));
    if (!BOOST_TEST(made.has_value())) {
        std::exit(boost::report_errors());
    }
    return std::move(*made);
}

/** A key pair's public key, parsed outside a check. */
secp::public_key public_of(secp::keypair const& key_pair) {
    auto const encoded = key_pair.public_key();
    auto const parsed = secp::parse_public_key(*encoded);
    if (!BOOST_TEST(parsed.has_value())) {
        std::exit(boost::report_errors());
    }
    return *parsed;
}

/**
 * A key pair moved from, whose every function refuses with `invalid_state`.
 *
 * @return The key pair, whose key went to an object destroyed since.
 */
secp::keypair moved_from() {
    auto source = keypair_of(0x0e);
    auto emptied = keypair_of(0x0f);
    emptied = std::move(source);
    // NOLINTNEXTLINE(bugprone-use-after-move): the moved-from key pair is the point
    return source;
}

/** A workspace of `size` bytes, on the heap. */
std::vector<std::byte> lent(std::size_t size) {
    return std::vector<std::byte>(size);
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1.hpp.
// ---------------------------------------------------------------------------------------------

/** basic_keypair::make, a secret of the wrong size included, generate, and public_key's two
 * operators. */
void cover_make_and_compare() {
    auto const secret_key = secret_bytes(0x11);
    covered("secp256k1::basic_keypair::make on secp256k1",
            [&] { BOOST_TEST(secp::keypair::make(secret_key).has_value()); });
    covered("secp256k1::basic_keypair::make with a short secret on secp256k1", [&] {
        BOOST_TEST(secp::keypair::make(std::span(secret_key).first(31)).error() ==
                   crypto::error::invalid_key_size);
    });
    // The system's source answers here; the refused draws are secp256k1_generate's, the program
    // built with the test seam.
    covered("secp256k1::basic_keypair::generate on secp256k1", "basic_keypair::generate",
            [&] { BOOST_TEST(secp::keypair::generate().has_value()); });
    auto const alice = public_of(keypair_of(0x11));
    auto const bob = public_of(keypair_of(0x12));
    covered("secp256k1::public_key::operator== on secp256k1",
            "secp256k1::operator==", [&] { BOOST_TEST(!(alice == bob)); });
    covered("secp256k1::public_key::operator<=> on secp256k1", "secp256k1::operator<=>",
            [&] { BOOST_TEST((alice <=> bob) != std::strong_ordering::equal); });
}

/** The key pair's public keys and signatures. */
void cover_keypair_signing() {
    auto const made = keypair_of(0x21);
    bytes32 const hash = secret_bytes(0x5a);
    bytes32 const randomness = secret_bytes(0x5b);
    covered("secp256k1::basic_keypair::xonly_public_key on secp256k1",
            [&] { BOOST_TEST(made.xonly_public_key().has_value()); });
    covered("secp256k1::basic_keypair::public_key on secp256k1",
            [&] { BOOST_TEST(made.public_key().has_value()); });
    covered("secp256k1::basic_keypair::public_key_uncompressed on secp256k1",
            [&] { BOOST_TEST(made.public_key_uncompressed().has_value()); });
    covered("secp256k1::basic_keypair::sign_schnorr on secp256k1",
            [&] { BOOST_TEST(made.sign_schnorr(hash, randomness).has_value()); });
    covered("secp256k1::basic_keypair::sign_ecdsa on secp256k1",
            [&] { BOOST_TEST(made.sign_ecdsa(hash).has_value()); });
    covered("secp256k1::basic_keypair::sign_ecdsa hedged on secp256k1",
            [&] { BOOST_TEST(made.sign_ecdsa(hash, randomness).has_value()); });
    covered("secp256k1::basic_keypair::sign_recoverable on secp256k1",
            [&] { BOOST_TEST(made.sign_recoverable(hash).has_value()); });
}

/** The key pair's public keys and signatures of a moved-from key pair, refused before the backend.
 */
void cover_keypair_signing_moved_from() {
    auto const empty = moved_from();
    bytes32 const hash = secret_bytes(0x5a);
    bytes32 const randomness = secret_bytes(0x5b);
    covered("secp256k1::basic_keypair::xonly_public_key moved from on secp256k1",
            [&] { BOOST_TEST(empty.xonly_public_key().error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::public_key moved from on secp256k1",
            [&] { BOOST_TEST(empty.public_key().error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::public_key_uncompressed moved from on secp256k1", [&] {
        BOOST_TEST(empty.public_key_uncompressed().error() == crypto::error::invalid_state);
    });
    covered("secp256k1::basic_keypair::sign_schnorr moved from on secp256k1", [&] {
        BOOST_TEST(empty.sign_schnorr(hash, randomness).error() == crypto::error::invalid_state);
    });
    covered("secp256k1::basic_keypair::sign_ecdsa moved from on secp256k1",
            [&] { BOOST_TEST(empty.sign_ecdsa(hash).error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::sign_ecdsa hedged moved from on secp256k1", [&] {
        BOOST_TEST(empty.sign_ecdsa(hash, randomness).error() == crypto::error::invalid_state);
    });
    covered("secp256k1::basic_keypair::sign_recoverable moved from on secp256k1", [&] {
        BOOST_TEST(empty.sign_recoverable(hash).error() == crypto::error::invalid_state);
    });
}

/** The key pair's three forms of ECDH and its tweak, each of a moved-from key pair too. */
void cover_keypair_agreement() {
    auto const made = keypair_of(0x31);
    auto tweaked = keypair_of(0x32);
    auto empty = moved_from();
    auto const peer = keypair_of(0x33).public_key();
    bytes32 const tweak = secret_bytes(0x07);
    covered("secp256k1::basic_keypair::ecdh on secp256k1",
            [&] { BOOST_TEST(made.ecdh(*peer).has_value()); });
    covered("secp256k1::basic_keypair::ecdh_x on secp256k1",
            [&] { BOOST_TEST(made.ecdh_x(*peer).has_value()); });
    covered("secp256k1::basic_keypair::ecdh_point on secp256k1",
            [&] { BOOST_TEST(made.ecdh_point(*peer).has_value()); });
    covered("secp256k1::basic_keypair::tweak_xonly on secp256k1",
            [&] { BOOST_TEST(tweaked.tweak_xonly(tweak).has_value()); });
    covered("secp256k1::basic_keypair::ecdh moved from on secp256k1",
            [&] { BOOST_TEST(empty.ecdh(*peer).error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::ecdh_x moved from on secp256k1",
            [&] { BOOST_TEST(empty.ecdh_x(*peer).error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::ecdh_point moved from on secp256k1",
            [&] { BOOST_TEST(empty.ecdh_point(*peer).error() == crypto::error::invalid_state); });
    covered("secp256k1::basic_keypair::tweak_xonly moved from on secp256k1",
            [&] { BOOST_TEST(empty.tweak_xonly(tweak).error() == crypto::error::invalid_state); });
}

/** parse_public_key, a key of the wrong size included, and serialize_public_key in both forms. */
void cover_public_keys() {
    auto const encoded = keypair_of(0x41).public_key();
    auto const parsed = secp::parse_public_key(*encoded);
    if (!BOOST_TEST(parsed.has_value())) {
        return;
    }
    covered("secp256k1::parse_public_key on secp256k1",
            [&] { BOOST_TEST(secp::parse_public_key(*encoded).has_value()); });
    covered("secp256k1::parse_public_key of a short key on secp256k1", [&] {
        BOOST_TEST(secp::parse_public_key(std::span(*encoded).first(32)).error() ==
                   crypto::error::invalid_public_key);
    });
    covered("secp256k1::serialize_public_key on secp256k1",
            [&] { BOOST_TEST(secp::serialize_public_key(*parsed) == *encoded); });
    covered("secp256k1::serialize_public_key uncompressed on secp256k1", [&] {
        BOOST_TEST(secp::serialize_public_key<secp::point_form::uncompressed>(*parsed)[0] == 0x04);
    });
}

/** recover and both verifications, each with input refused before the backend's work too. */
void cover_verification() {
    auto const signer = keypair_of(0x51);
    bytes32 const hash = secret_bytes(0x5c);
    auto const xonly_key = signer.xonly_public_key();
    auto const public_key = signer.public_key();
    auto const schnorr = signer.sign_schnorr(hash, secret_bytes(0x01));
    auto const ecdsa = signer.sign_ecdsa(hash);
    auto recoverable = signer.sign_recoverable(hash);
    if (!BOOST_TEST(xonly_key.has_value()) || !BOOST_TEST(public_key.has_value()) ||
        !BOOST_TEST(schnorr.has_value()) || !BOOST_TEST(ecdsa.has_value()) ||
        !BOOST_TEST(recoverable.has_value())) {
        return;
    }
    bytes32 const not_a_key = secret_bytes(0xff);
    covered("secp256k1::recover on secp256k1",
            [&] { BOOST_TEST(secp::recover(*recoverable, hash).has_value()); });
    covered("secp256k1::verify_schnorr on secp256k1",
            [&] { BOOST_TEST(secp::verify_schnorr(*schnorr, hash, *xonly_key).has_value()); });
    covered("secp256k1::verify_ecdsa on secp256k1",
            [&] { BOOST_TEST(secp::verify_ecdsa(*ecdsa, hash, *public_key).has_value()); });
    covered("secp256k1::verify_schnorr with a key off the curve on secp256k1", [&] {
        BOOST_TEST(secp::verify_schnorr(*schnorr, hash, not_a_key).error() ==
                   crypto::error::invalid_public_key);
    });
    covered("secp256k1::verify_ecdsa with a short key on secp256k1", [&] {
        BOOST_TEST(secp::verify_ecdsa(*ecdsa, hash, std::span(*public_key).first(32)).error() ==
                   crypto::error::invalid_public_key);
    });
    (*recoverable)[64] = 4;
    covered("secp256k1::recover with a recovery id of 4 on secp256k1", [&] {
        BOOST_TEST(secp::recover(*recoverable, hash).error() == crypto::error::invalid_signature);
    });
}

/** ECDSA's DER and low-S forms and the free x-only tweak, a refusal of each. */
void cover_signature_forms() {
    auto const signer = keypair_of(0x61);
    auto const ecdsa = signer.sign_ecdsa(secret_bytes(0x5d));
    auto const xonly_key = signer.xonly_public_key();
    if (!BOOST_TEST(ecdsa.has_value()) || !BOOST_TEST(xonly_key.has_value())) {
        return;
    }
    std::array<std::uint8_t, secp::max_der_size> der{};
    std::size_t der_size = 0;
    std::array<std::uint8_t, 64> const zero_signature{};
    bytes32 const tweak = secret_bytes(0x08);
    covered("secp256k1::to_der on secp256k1", [&] {
        auto const written = secp::to_der(*ecdsa, der);
        if (BOOST_TEST(written.has_value())) {
            der_size = *written;
        }
    });
    covered("secp256k1::from_der on secp256k1",
            [&] { BOOST_TEST(secp::from_der(std::span(der).first(der_size)).has_value()); });
    covered("secp256k1::normalize_ecdsa on secp256k1",
            [&] { BOOST_TEST(secp::normalize_ecdsa(*ecdsa).has_value()); });
    covered("secp256k1::tweak_xonly on secp256k1",
            [&] { BOOST_TEST(secp::tweak_xonly(*xonly_key, tweak).has_value()); });
    covered("secp256k1::to_der into a short output on secp256k1", [&] {
        BOOST_TEST(secp::to_der(*ecdsa, std::span(der).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("secp256k1::from_der of no byte on secp256k1", [&] {
        BOOST_TEST(secp::from_der(std::span(der).first(0)).error() ==
                   crypto::error::invalid_signature);
    });
    covered("secp256k1::normalize_ecdsa of a zero signature on secp256k1", [&] {
        BOOST_TEST(secp::normalize_ecdsa(zero_signature).error() ==
                   crypto::error::invalid_signature);
    });
    covered("secp256k1::tweak_xonly of a key off the curve on secp256k1", [&] {
        BOOST_TEST(secp::tweak_xonly(secret_bytes(0xff), tweak).error() ==
                   crypto::error::invalid_public_key);
    });
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1/ellswift.hpp.
// ---------------------------------------------------------------------------------------------

/** ElligatorSwift's encoding, decoding, creation and exchange, of a moved-from key pair too. */
void cover_ellswift() {
    auto const initiator = keypair_of(0x71);
    auto const responder = keypair_of(0x72);
    auto const empty = moved_from();
    bytes32 const randomness = secret_bytes(0x09);
    auto const initiator_encoding = secp::ellswift_create(initiator, randomness);
    auto const responder_encoding = secp::ellswift_create(responder, randomness);
    if (!BOOST_TEST(initiator_encoding.has_value()) ||
        !BOOST_TEST(responder_encoding.has_value())) {
        return;
    }
    auto const responder_key = public_of(responder);
    std::array<std::uint8_t, secp::ellswift_size> encoded{};
    covered("secp256k1::ellswift_encode on secp256k1",
            [&] { encoded = secp::ellswift_encode(responder_key, randomness); });
    BOOST_TEST(secp::ellswift_decode(encoded) == responder_key);
    // Each check calls the function alone: the comparison, guarded too, runs after it.
    std::optional<secp::public_key> decoded;
    covered("secp256k1::ellswift_decode on secp256k1",
            [&] { decoded = secp::ellswift_decode(*responder_encoding); });
    BOOST_TEST((decoded && *decoded == responder_key));
    covered("secp256k1::ellswift_create on secp256k1",
            [&] { BOOST_TEST(secp::ellswift_create(initiator, randomness).has_value()); });
    covered("secp256k1::ellswift_xdh on secp256k1", [&] {
        BOOST_TEST(secp::ellswift_xdh(initiator, *initiator_encoding, *responder_encoding,
                                      secp::ellswift_party::initiator)
                       .has_value());
    });
    covered("secp256k1::ellswift_create moved from on secp256k1", [&] {
        BOOST_TEST(secp::ellswift_create(empty, randomness).error() ==
                   crypto::error::invalid_state);
    });
    covered("secp256k1::ellswift_xdh moved from on secp256k1", [&] {
        BOOST_TEST(secp::ellswift_xdh(empty, *initiator_encoding, *responder_encoding,
                                      secp::ellswift_party::responder)
                       .error() == crypto::error::invalid_state);
    });
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1/formats.hpp.
// ---------------------------------------------------------------------------------------------

/**
 * SPKI and PKCS#8, each refused once before the backend too: the decoders call equal, and
 * decode_pkcs8 also make and encode_pkcs8, so only their refusals show their own guards.
 */
void cover_formats() {
    auto const made = keypair_of(0x81);
    auto const empty = moved_from();
    auto const key = public_of(made);
    std::array<std::uint8_t, secp::max_spki_size> spki{};
    std::size_t spki_size = 0;
    std::array<std::uint8_t, secp::max_pkcs8_size> pkcs8{};
    covered("secp256k1::encode_spki on secp256k1", [&] {
        auto const written = secp::encode_spki(key, spki);
        if (BOOST_TEST(written.has_value())) {
            spki_size = *written;
        }
    });
    covered("secp256k1::decode_spki on secp256k1",
            [&] { BOOST_TEST(secp::decode_spki(std::span(spki).first(spki_size)).has_value()); });
    covered("secp256k1::encode_pkcs8 on secp256k1",
            [&] { BOOST_TEST(secp::encode_pkcs8(made, pkcs8).has_value()); });
    covered("secp256k1::decode_pkcs8 on secp256k1",
            [&] { BOOST_TEST(secp::decode_pkcs8(pkcs8).has_value()); });
    covered("secp256k1::encode_spki into a short output on secp256k1", [&] {
        BOOST_TEST(secp::encode_spki(key, std::span(spki).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("secp256k1::decode_spki of a short encoding on secp256k1", [&] {
        BOOST_TEST(secp::decode_spki(std::span(spki).first(1)).error() ==
                   crypto::error::invalid_encoding);
    });
    covered("secp256k1::encode_pkcs8 moved from on secp256k1", [&] {
        BOOST_TEST(secp::encode_pkcs8(empty, pkcs8).error() == crypto::error::invalid_state);
    });
    covered("secp256k1::decode_pkcs8 of a short encoding on secp256k1", [&] {
        BOOST_TEST(secp::decode_pkcs8(std::span(pkcs8).first(1)).error() ==
                   crypto::error::invalid_encoding);
    });
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1/musig.hpp.
// ---------------------------------------------------------------------------------------------

/** MuSig2's aggregate key of two keys: its four members, and key_aggregate refused. */
void cover_musig_key() {
    std::array<secp::public_key, 2> const keys{
        public_of(keypair_of(0x91)),
        public_of(keypair_of(0x92)),
    };
    auto space = lent(musig::workspace_size(keys.size()));
    covered("musig::key_aggregate on secp256k1",
            [&] { BOOST_TEST(musig::key_aggregate(keys, space).has_value()); });
    covered("musig::key_aggregate of no key on secp256k1", [&] {
        BOOST_TEST(musig::key_aggregate(std::span(keys).first(0), space).error() ==
                   crypto::error::invalid_input_size);
    });
    auto aggregate = musig::key_aggregate(keys, space);
    if (!BOOST_TEST(aggregate.has_value())) {
        return;
    }
    bytes32 const tweak = secret_bytes(0x0a);
    bytes32 const too_large = secret_bytes(0xff);
    // xonly_public_key calls full_public_key, guarded too, on its one path: the check requires
    // that the first guard entered is xonly_public_key's own.
    bytes32 xonly_key{};
    covered("musig::aggregate_key::xonly_public_key on secp256k1",
            [&] { xonly_key = aggregate->xonly_public_key(); });
    BOOST_TEST(xonly_key != bytes32{});
    std::optional<secp::public_key> full_key;
    covered("musig::aggregate_key::full_public_key on secp256k1",
            [&] { full_key = aggregate->full_public_key(); });
    BOOST_TEST((full_key && !(*full_key == keys[0])));
    covered("musig::aggregate_key::tweak_add on secp256k1",
            [&] { BOOST_TEST(aggregate->tweak_add(tweak).has_value()); });
    covered("musig::aggregate_key::tweak_xonly_add on secp256k1",
            [&] { BOOST_TEST(aggregate->tweak_xonly_add(tweak).has_value()); });
    covered("musig::aggregate_key::tweak_add of a tweak too large on secp256k1", [&] {
        BOOST_TEST(aggregate->tweak_add(too_large).error() == crypto::error::invalid_secret_key);
    });
    covered("musig::aggregate_key::tweak_xonly_add of a tweak too large on secp256k1", [&] {
        BOOST_TEST(aggregate->tweak_xonly_add(too_large).error() ==
                   crypto::error::invalid_secret_key);
    });
}

/** MuSig2's encodings: each parse, a short one refused, and each serialisation. */
void cover_musig_encodings(musig::public_nonce const& public_nonce,
                           musig::aggregate_nonce const& aggregate_nonce,
                           musig::partial_signature const& part) {
    std::array<std::uint8_t, musig::public_nonce_size> public_bytes{};
    std::array<std::uint8_t, musig::aggregate_nonce_size> aggregate_bytes{};
    std::array<std::uint8_t, musig::partial_signature_size> part_bytes{};
    covered("musig::serialize_public_nonce on secp256k1",
            [&] { public_bytes = musig::serialize_public_nonce(public_nonce); });
    covered("musig::serialize_aggregate_nonce on secp256k1",
            [&] { aggregate_bytes = musig::serialize_aggregate_nonce(aggregate_nonce); });
    covered("musig::serialize_partial_signature on secp256k1",
            [&] { part_bytes = musig::serialize_partial_signature(part); });
    covered("musig::parse_public_nonce on secp256k1",
            [&] { BOOST_TEST(musig::parse_public_nonce(public_bytes).has_value()); });
    covered("musig::parse_aggregate_nonce on secp256k1",
            [&] { BOOST_TEST(musig::parse_aggregate_nonce(aggregate_bytes).has_value()); });
    covered("musig::parse_partial_signature on secp256k1",
            [&] { BOOST_TEST(musig::parse_partial_signature(part_bytes).has_value()); });
    covered("musig::parse_public_nonce of a short encoding on secp256k1", [&] {
        BOOST_TEST(musig::parse_public_nonce(std::span(public_bytes).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("musig::parse_aggregate_nonce of a short encoding on secp256k1", [&] {
        BOOST_TEST(musig::parse_aggregate_nonce(std::span(aggregate_bytes).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
    covered("musig::parse_partial_signature of a short encoding on secp256k1", [&] {
        BOOST_TEST(musig::parse_partial_signature(std::span(part_bytes).first(1)).error() ==
                   crypto::error::invalid_input_size);
    });
}

/** A MuSig2 signature of two signers, as each step of its round leaves it. */
struct musig_round {
    /** The first signer. */
    secp::keypair alice = keypair_of(0x93);
    /** The second signer. */
    secp::keypair bob = keypair_of(0x94);
    /** Their public keys, in the order they are aggregated. */
    std::array<secp::public_key, 2> keys{public_of(alice), public_of(bob)};
    /** The 32-byte message signed. */
    bytes32 message = secret_bytes(0x5e);
    /** The aggregate of their keys. */
    std::optional<musig::aggregate_key> aggregate;
    /** The first signer's nonce. */
    std::optional<musig::nonce_pair> alice_nonce;
    /** The second signer's nonce. */
    std::optional<musig::nonce_pair> bob_nonce;
    /** A nonce of the second signer, which a moved-from key pair is refused to sign with. */
    std::optional<musig::nonce_pair> spare_nonce;
    /** The sum of both public nonces. */
    std::optional<musig::aggregate_nonce> nonce_sum;
    /** The session of the message. */
    std::optional<musig::session> session;
    /** The partial signatures, the first signer's first. */
    std::vector<musig::partial_signature> parts;

    /** Both public nonces, the first signer's first; both nonces are made. */
    [[nodiscard]] std::array<musig::public_nonce, 2> publics() const {
        return {alice_nonce->public_part, bob_nonce->public_part};
    }
};

/**
 * MuSig2's first round, as secp256k1_musig_test.cpp builds it: nonce_gen, of a moved-from key
 * pair too, and nonce_aggregate, of no nonce too.
 *
 * @param round The round, whose aggregate key is made.
 * @return Whether every nonce and their sum are made.
 */
bool cover_musig_nonces(musig_round& round) {
    auto const empty = moved_from();
    covered("musig::nonce_gen on secp256k1", [&] {
        auto made = musig::nonce_gen(round.alice, *round.aggregate, round.message);
        if (BOOST_TEST(made.has_value())) {
            round.alice_nonce.emplace(std::move(*made));
        }
    });
    covered("musig::nonce_gen moved from on secp256k1", [&] {
        BOOST_TEST(musig::nonce_gen(empty, *round.aggregate, round.message).error() ==
                   crypto::error::invalid_state);
    });
    auto bob_nonce = musig::nonce_gen(round.bob, *round.aggregate, round.message);
    auto spare_nonce = musig::nonce_gen(round.bob, *round.aggregate, round.message);
    if (!round.alice_nonce || !BOOST_TEST(bob_nonce.has_value()) ||
        !BOOST_TEST(spare_nonce.has_value())) {
        return false;
    }
    round.bob_nonce.emplace(std::move(*bob_nonce));
    round.spare_nonce.emplace(std::move(*spare_nonce));
    auto const publics = round.publics();
    auto space = lent(musig::workspace_size(publics.size()));
    covered("musig::nonce_aggregate on secp256k1", [&] {
        auto const summed = musig::nonce_aggregate(publics, space);
        if (BOOST_TEST(summed.has_value())) {
            round.nonce_sum = *summed;
        }
    });
    covered("musig::nonce_aggregate of no nonce on secp256k1", [&] {
        BOOST_TEST(musig::nonce_aggregate(std::span(publics).first(0), space).error() ==
                   crypto::error::invalid_input_size);
    });
    return round.nonce_sum.has_value();
}

/**
 * MuSig2's second round: nonce_process, and partial_sign, of a moved-from key pair too.
 *
 * @param round The round, whose nonces and their sum are made.
 * @return Whether the session and both partial signatures are made.
 */
bool cover_musig_signing(musig_round& round) {
    auto const empty = moved_from();
    covered("musig::nonce_process on secp256k1", [&] {
        auto const processed =
            musig::nonce_process(*round.nonce_sum, round.message, *round.aggregate);
        if (BOOST_TEST(processed.has_value())) {
            round.session = *processed;
        }
    });
    if (!round.session) {
        return false;
    }
    covered("musig::partial_sign on secp256k1", [&] {
        auto const part =
            musig::partial_sign(round.alice, std::move(round.alice_nonce->secret_part),
                                *round.aggregate, *round.session);
        if (BOOST_TEST(part.has_value())) {
            round.parts.push_back(*part);
        }
    });
    covered("musig::partial_sign moved from on secp256k1", [&] {
        BOOST_TEST(musig::partial_sign(empty, std::move(round.spare_nonce->secret_part),
                                       *round.aggregate, *round.session)
                       .error() == crypto::error::invalid_state);
    });
    auto const bob_part = musig::partial_sign(round.bob, std::move(round.bob_nonce->secret_part),
                                              *round.aggregate, *round.session);
    if (round.parts.empty() || !BOOST_TEST(bob_part.has_value())) {
        return false;
    }
    round.parts.push_back(*bob_part);
    return true;
}

/**
 * The end of a MuSig2 round: partial_signature_verify, and partial_signature_aggregate, of no
 * part too; then the encodings of its nonces and signatures.
 *
 * @param round The round, whose partial signatures are made.
 */
void cover_musig_aggregation(musig_round const& round) {
    auto const publics = round.publics();
    covered("musig::partial_signature_verify on secp256k1", [&] {
        BOOST_TEST(musig::partial_signature_verify(round.parts[0], publics[0], round.keys[0],
                                                   *round.aggregate, *round.session)
                       .has_value());
    });
    auto space = lent(musig::workspace_size(round.parts.size()));
    covered("musig::partial_signature_aggregate on secp256k1", [&] {
        BOOST_TEST(
            musig::partial_signature_aggregate(*round.session, round.parts, space).has_value());
    });
    covered("musig::partial_signature_aggregate of no part on secp256k1", [&] {
        BOOST_TEST(musig::partial_signature_aggregate(*round.session,
                                                      std::span(round.parts).first(0), space)
                       .error() == crypto::error::invalid_input_size);
    });
    cover_musig_encodings(publics[0], *round.nonce_sum, round.parts[0]);
}

/** A whole MuSig2 round of two signers, as secp256k1_musig_test.cpp builds it. */
void cover_musig_round() {
    musig_round round;
    auto space = lent(musig::workspace_size(round.keys.size()));
    auto const aggregate = musig::key_aggregate(round.keys, space);
    if (!BOOST_TEST(aggregate.has_value())) {
        return;
    }
    round.aggregate = *aggregate;
    if (cover_musig_nonces(round) && cover_musig_signing(round)) {
        cover_musig_aggregation(round);
    }
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1/silent_payments.hpp.
// ---------------------------------------------------------------------------------------------

/** A label lookup that knows one label, as a wallet's does. */
struct one_label {
    /** The label known. */
    sp::label known;

    /**
     * The label's tweak when the candidate is its point.
     *
     * @param candidate The label's point libsecp256k1 asks about.
     * @return The tweak, or nothing.
     */
    [[nodiscard]] std::optional<std::span<std::uint8_t const, 32>> operator()(
        std::span<std::uint8_t const, 33> candidate) const noexcept {
        if (std::ranges::equal(known.point, candidate)) {
            return std::span<std::uint8_t const, 32>(known.tweak);
        }
        return std::nullopt;
    }
};

/** A silent payment, as each step of sending and receiving it leaves it. */
struct silent_payment {
    /** The sender, with one plain input. */
    secp::keypair sender = keypair_of(0xa1);
    /** The recipient's scan key pair. */
    secp::keypair scan_key = keypair_of(0xa2);
    /** The recipient's spend key. */
    secp::public_key spend_key = public_of(keypair_of(0xa3));
    /** The smallest outpoint of the sender's inputs. */
    std::array<std::uint8_t, sp::outpoint_size> outpoint{1, 2, 3};
    /** The recipient's label. */
    std::optional<sp::label> made_label;
    /** The spend key with the label, which the sender pays. */
    std::optional<secp::public_key> labelled_key;
    /** The output the sender made. */
    std::array<bytes32, 1> outputs{};
    /** The summary of the sender's inputs, which the recipient scans with. */
    std::optional<sp::prevouts_summary> summary;
};

/**
 * create_label, of a moved-from key pair too, and create_labeled_spend_key.
 *
 * @param payment The payment, with no label yet.
 * @return Whether the label and the labelled spend key are made.
 */
bool cover_silent_payment_labels(silent_payment& payment) {
    auto const empty = moved_from();
    covered("silent_payments::create_label on secp256k1", [&] {
        auto const created = sp::create_label(payment.scan_key, 1);
        if (BOOST_TEST(created.has_value())) {
            payment.made_label = *created;
        }
    });
    covered("silent_payments::create_label moved from on secp256k1", [&] {
        BOOST_TEST(sp::create_label(empty, 1).error() == crypto::error::invalid_state);
    });
    if (!payment.made_label) {
        return false;
    }
    covered("silent_payments::create_labeled_spend_key on secp256k1", [&] {
        auto const created = sp::create_labeled_spend_key(payment.spend_key, *payment.made_label);
        if (BOOST_TEST(created.has_value())) {
            payment.labelled_key = *created;
        }
    });
    return payment.labelled_key.has_value();
}

/**
 * Sending: create_outputs to the labelled address, to no recipient too, and
 * make_prevouts_summary of the sender's key, of no input too.
 *
 * @param payment The payment, whose labelled spend key is made.
 * @return Whether the output and the summary are made.
 */
bool cover_silent_payment_sending(silent_payment& payment) {
    auto const scan_public = public_of(payment.scan_key);
    sp::recipient const address{.scan_key = scan_public, .spend_key = *payment.labelled_key};
    std::array<sp::recipient, 1> const recipients{address};
    std::array<secp::keypair const*, 1> const plain{&payment.sender};
    auto send_space = lent(sp::send_workspace_size(1, 0, 1));
    covered("silent_payments::create_outputs on secp256k1", [&] {
        BOOST_TEST(
            sp::create_outputs(recipients, payment.outpoint, {}, plain, payment.outputs, send_space)
                .has_value());
    });
    covered("silent_payments::create_outputs to no recipient on secp256k1", [&] {
        BOOST_TEST(sp::create_outputs(std::span(recipients).first(0), payment.outpoint, {}, plain,
                                      std::span(payment.outputs).first(0), send_space)
                       .error() == crypto::error::invalid_input_size);
    });
    std::array<secp::public_key, 1> const sender_keys{public_of(payment.sender)};
    auto summary_space = lent(sp::summary_workspace_size(0, 1));
    covered("silent_payments::make_prevouts_summary on secp256k1", [&] {
        auto const made =
            sp::make_prevouts_summary(payment.outpoint, {}, sender_keys, summary_space);
        if (BOOST_TEST(made.has_value())) {
            payment.summary = *made;
        }
    });
    covered("silent_payments::make_prevouts_summary of no input on secp256k1", [&] {
        BOOST_TEST(sp::make_prevouts_summary(payment.outpoint, {}, std::span(sender_keys).first(0),
                                             summary_space)
                       .error() == crypto::error::invalid_input_size);
    });
    return payment.summary.has_value();
}

/**
 * Receiving: scan_outputs with no label, with a lookup that finds the output (the program's
 * lookup runs inside the guard, ruling R6), and of no output.
 *
 * @param payment The payment, whose output and summary are made.
 */
void cover_silent_payment_scanning(silent_payment const& payment) {
    std::array<sp::found_output, 1> found{};
    auto space = lent(sp::scan_workspace_size(1));
    std::span<bytes32 const> const outputs(payment.outputs);
    one_label const lookup{.known = *payment.made_label};
    covered("silent_payments::scan_outputs on secp256k1", [&] {
        BOOST_TEST(sp::scan_outputs(payment.scan_key, payment.spend_key, *payment.summary, outputs,
                                    found, space)
                       .has_value());
    });
    covered("silent_payments::scan_outputs with a label lookup on secp256k1", [&] {
        auto const count = sp::scan_outputs(payment.scan_key, payment.spend_key, *payment.summary,
                                            outputs, found, space, lookup);
        if (BOOST_TEST(count.has_value())) {
            BOOST_TEST_EQ(*count, 1U);
        }
    });
    covered("silent_payments::scan_outputs of no output on secp256k1", [&] {
        BOOST_TEST(sp::scan_outputs(payment.scan_key, payment.spend_key, *payment.summary,
                                    outputs.first(0), found, space)
                       .error() == crypto::error::invalid_input_size);
    });
}

/**
 * Silent payments, as secp256k1_silent_payments_test.cpp builds them: a labelled address, an
 * output created to it, and the recipient's scan that finds it.
 */
void cover_silent_payments() {
    silent_payment payment;
    if (cover_silent_payment_labels(payment) && cover_silent_payment_sending(payment)) {
        cover_silent_payment_scanning(payment);
    }
}

// ---------------------------------------------------------------------------------------------
// curves/secp256k1/tweak.hpp.
// ---------------------------------------------------------------------------------------------

/** The tweaks, negations and combination of keys, and pubkey_combine refused. */
void cover_tweaks() {
    bytes32 const secret_key = secret_bytes(0xb1);
    bytes32 const tweak = secret_bytes(0x0b);
    std::array<secp::public_key, 2> const keys{
        public_of(keypair_of(0xb2)),
        public_of(keypair_of(0xb3)),
    };
    covered("secp256k1::seckey_tweak_add on secp256k1",
            [&] { BOOST_TEST(secp::seckey_tweak_add(secret_key, tweak).has_value()); });
    covered("secp256k1::seckey_tweak_mul on secp256k1",
            [&] { BOOST_TEST(secp::seckey_tweak_mul(secret_key, tweak).has_value()); });
    covered("secp256k1::seckey_negate on secp256k1",
            [&] { BOOST_TEST(secp::seckey_negate(secret_key).has_value()); });
    covered("secp256k1::pubkey_tweak_add on secp256k1",
            [&] { BOOST_TEST(secp::pubkey_tweak_add(keys[0], tweak).has_value()); });
    covered("secp256k1::pubkey_tweak_mul on secp256k1",
            [&] { BOOST_TEST(secp::pubkey_tweak_mul(keys[0], tweak).has_value()); });
    boost::system::result<secp::public_key> negated = crypto::error::backend_failure;
    covered("secp256k1::pubkey_negate on secp256k1",
            [&] { negated = secp::pubkey_negate(keys[0]); });
    BOOST_TEST((negated && !(*negated == keys[0])));
    auto space = lent(secp::combine_workspace_size(keys.size()));
    covered("secp256k1::pubkey_combine on secp256k1",
            [&] { BOOST_TEST(secp::pubkey_combine(keys, space).has_value()); });
    covered("secp256k1::pubkey_combine of no key on secp256k1", [&] {
        BOOST_TEST(secp::pubkey_combine(std::span(keys).first(0), space).error() ==
                   crypto::error::invalid_input_size);
    });
}

// ---------------------------------------------------------------------------------------------
// An exception through the guard.
// ---------------------------------------------------------------------------------------------

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
/**
 * Sets the thread's DIT, or clears it, where the CPU has it; nothing elsewhere.
 *
 * @param set Whether to set it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (!crypto::detail::cpu_has_dit()) {
        return;
    }
    crypto::detail::write_dit(set ? crypto::detail::dit_bit : 0);
#endif
}

/** A memory resource whose every allocation throws `std::bad_alloc`. */
class throwing_resource final : public std::pmr::memory_resource {
private:
    void* do_allocate(std::size_t /*bytes*/, std::size_t /*alignment*/) override {
        throw std::bad_alloc();
    }

    void do_deallocate(void* /*pointer*/, std::size_t /*bytes*/,
                       std::size_t /*alignment*/) override {}

    [[nodiscard]] bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override {
        return this == &other;
    }
};

/**
 * Runs `call`, which allocates from a throwing_resource, and reports whether `std::bad_alloc`
 * reached it.
 *
 * @param call The call.
 * @return Whether the call threw `std::bad_alloc`.
 */
template <class Call>
bool throws_bad_alloc(Call const& call) {
    try {
        call();
    } catch (std::bad_alloc const&) {
        return true;
    }
    return false;
}

/**
 * An exception from the memory resource unwinds through basic_keypair::make's guard and through
 * decode_pkcs8's: DIT is clear after it from clear, and still set from set (ruling R6).
 */
void throwing_resource_restores_state() {
    throwing_resource resource;
    auto const secret_key = secret_bytes(0xc1);
    std::array<std::uint8_t, secp::max_pkcs8_size> pkcs8{};
    if (!BOOST_TEST(secp::encode_pkcs8(keypair_of(0xc1), pkcs8).has_value())) {
        return;
    }
    auto const make = [&] { static_cast<void>(secp::keypair::make(secret_key, &resource)); };
    // decode_pkcs8 reaches the resource through make, guarded too: its own entry is checked by
    // cover_formats' refusal; here the subject is the state the unwinding leaves.
    auto const decode = [&] {
        static_cast<void>(secp::decode_pkcs8(std::span<std::uint8_t const>(pkcs8), &resource));
    };
    for (bool const set : {false, true}) {
        std::string const from = set ? " from set" : " from clear";
        force_dit(set);
        covered("secp256k1::basic_keypair::make with a throwing resource" + from + " on secp256k1",
                [&] { BOOST_TEST(throws_bad_alloc(make)); });
        BOOST_TEST_EQ(crypto::detail::dit_is_set(), set && crypto::detail::cpu_has_dit());
        covered("secp256k1::decode_pkcs8 with a throwing resource" + from + " on secp256k1",
                [&] { BOOST_TEST(throws_bad_alloc(decode)); });
        BOOST_TEST_EQ(crypto::detail::dit_is_set(), set && crypto::detail::cpu_has_dit());
    }
    force_dit(false);
    BOOST_TEST(!crypto::detail::dit_is_set());
}
#endif

}  // namespace

int main() {
    cover_make_and_compare();
    cover_keypair_signing();
    cover_keypair_signing_moved_from();
    cover_keypair_agreement();
    cover_public_keys();
    cover_verification();
    cover_signature_forms();
    cover_ellswift();
    cover_formats();
    cover_musig_key();
    cover_musig_round();
    cover_silent_payments();
    cover_tweaks();
#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    throwing_resource_restores_state();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
