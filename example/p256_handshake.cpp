// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A signed handshake between two peers on P-256, as a browser's WebCrypto can take part in it:
// each peer keeps a long-lived identity key pair as its scalar, and makes a fresh key pair for
// the session; each sends its two public keys raw, signs the SHA-256 digest of the handshake's
// bytes with its identity, low S, and checks the other's signature, low S first; both derive the
// session key from ECDH's x through HKDF-SHA-256. Every scalar is fixed, so that the output is;
// a real program draws its key pairs with keypair::generate(). What is signed, when, and the
// low-S rule are a protocol's: this one is an example, not webcpp::trystero's.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/secret.hpp>

#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hkdf.hpp>

#include <boost/system/result.hpp>

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
namespace p256 = webcpp::crypto::curves::p256;

namespace {

// Prints bytes in hex after a name, 32 bytes (64 digits) to a line, the lines after the first
// indented under the first, so that a long value stays readable on a narrow page.
void print(char const* name, std::span<std::uint8_t const> bytes) {
    int const indent = std::printf("%s ", name);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0 && i % 32 == 0) {
            std::printf("\n%*s", indent, "");
        }
        std::printf("%02x", static_cast<unsigned>(bytes[i]));
    }
    std::printf("\n");
}

// A text's bytes.
std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): a text's bytes
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

// A key pair whose scalar is one byte repeated: fixed, so that the output is fixed.
boost::system::result<p256::keypair> from_byte(std::uint8_t fill) {
    std::array<std::uint8_t, p256::secret_key_size> scalar{};
    scalar.fill(fill);
    return p256::keypair::make(scalar);
}

// What a peer sends: its identity's public key and its session key pair's, raw, as WebCrypto's
// exportKey("raw") writes them.
struct hello {
    std::array<std::uint8_t, p256::public_key_size> identity{};
    std::array<std::uint8_t, p256::public_key_size> session{};
};

// tag::transcript[]
// The handshake's bytes, both hellos in the initiator's order, hashed with SHA-256: the digest
// both sides sign, as WebCrypto's ECDSA with SHA-256 hashes what it signs.
boost::system::result<std::array<std::uint8_t, p256::digest_size>> transcript_digest(
    hello const& initiator, hello const& responder) {
    std::array<std::uint8_t, 4 * p256::public_key_size> bytes{};
    auto const keys = std::to_array(
        {initiator.identity, initiator.session, responder.identity, responder.session});
    for (std::size_t i = 0; i < keys.size(); ++i) {
        std::ranges::copy(keys[i], std::span(bytes).subspan(i * p256::public_key_size).begin());
    }
    std::array<std::uint8_t, p256::digest_size> digest{};
    auto const hashed = webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(digest, bytes);
    if (!hashed) {
        return hashed.error();
    }
    return digest;
}

// end::transcript[]

// A peer: its identity key pair, made again from the scalar it kept, and this session's key pair.
struct peer {
    p256::keypair identity;
    p256::keypair session;

    // What it sends.
    [[nodiscard]] boost::system::result<hello> greet() const {
        auto const identity_key = identity.public_key();
        auto const session_key = session.public_key();
        if (!identity_key || !session_key) {
            return crypto::error::invalid_state;
        }
        return hello{
            .identity = identity_key->uncompressed(),
            .session = session_key->uncompressed(),
        };
    }

    // tag::sign[]
    // Signs the transcript's digest with the identity, in the low-S form the protocol requires.
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, p256::signature_size>> sign(
        std::span<std::uint8_t const, p256::digest_size> digest) const {
        auto const signature = identity.sign_ecdsa(digest);
        if (!signature) {
            return signature.error();
        }
        return p256::normalize_ecdsa(*signature);
    }

    // end::sign[]

    // tag::receive[]
    // Checks the other peer's signature of the transcript: low S first, as the protocol requires,
    // then the signature itself, with the identity key the peer sent, made into a public_key.
    // A real protocol also checks that this identity is the one it expects.
    static boost::system::result<void> check(
        hello const& other, std::span<std::uint8_t const, p256::digest_size> digest,
        std::span<std::uint8_t const, p256::signature_size> signature) {
        auto const identity_key = p256::public_key::make(other.identity);
        if (!identity_key) {
            return identity_key.error();
        }
        if (auto const low = p256::check_low_s(signature); !low) {
            return low;
        }
        return p256::verify_ecdsa(signature, digest, *identity_key);
    }

    // end::receive[]

    // tag::session[]
    // The session key: ECDH's x of the two session key pairs, through HKDF-SHA-256 with the
    // transcript's digest as the salt, so that the key is bound to this handshake.
    [[nodiscard]] boost::system::result<crypto::secret<32>> session_key(
        hello const& other, std::span<std::uint8_t const, p256::digest_size> digest) const {
        auto const other_key = p256::public_key::make(other.session);
        if (!other_key) {
            return other_key.error();
        }
        auto const x = session.ecdh_x(*other_key);
        if (!x) {
            return x.error();
        }
        crypto::secret<32> key;
        auto const derived = webcpp::hash::hkdf<webcpp::hash::hmac_sha2_256>(
            key.writable(), digest, x->bytes(), bytes_of("example handshake v1 session key"));
        if (!derived) {
            return derived.error();
        }
        return key;
    }

    // end::session[]
};

// tag::identity[]
// A peer whose identity was kept as its 32-byte scalar: the key pair is made again from it.
boost::system::result<peer> peer_from(std::uint8_t identity_fill, std::uint8_t session_fill) {
    auto const first = from_byte(identity_fill);
    auto const kept = first ? first->secret_scalar() : first.error();
    if (!kept) {
        return kept.error();
    }
    auto identity = p256::keypair::make(kept->bytes());
    auto session = from_byte(session_fill);
    if (!identity || !session) {
        return crypto::error::backend_failure;
    }
    return peer{.identity = std::move(*identity), .session = std::move(*session)};
}

// end::identity[]

}  // namespace

int main() {
    auto const alice = peer_from(0x16, 0x33);
    auto const bob = peer_from(0x22, 0x44);
    auto const alice_hello = alice ? alice->greet() : alice.error();
    auto const bob_hello = bob ? bob->greet() : bob.error();
    if (!alice_hello || !bob_hello) {
        std::printf("failed\n");
        return 1;
    }
    // Alice starts: both hash the same bytes, in her order.
    auto const digest = transcript_digest(*alice_hello, *bob_hello);
    if (!digest) {
        std::printf("failed\n");
        return 1;
    }
    print("transcript ", *digest);
    auto const alice_signature = alice->sign(*digest);
    auto const bob_signature = bob->sign(*digest);
    if (!alice_signature || !bob_signature) {
        std::printf("failed\n");
        return 1;
    }
    print("alice signs", *alice_signature);
    print("bob signs  ", *bob_signature);
    bool const alice_checked = peer::check(*alice_hello, *digest, *alice_signature).has_value();
    bool const bob_checked = peer::check(*bob_hello, *digest, *bob_signature).has_value();
    std::printf("bob checks alice: %s; alice checks bob: %s\n", alice_checked ? "ok" : "refused",
                bob_checked ? "ok" : "refused");

    // The same digest signed without normalize_ecdsa: its S, as the computation gave it, is high
    // here, so the receiver refuses it before it verifies it, though it would verify.
    auto const raw = alice->identity.sign_ecdsa(*digest);
    if (!raw) {
        std::printf("failed\n");
        return 1;
    }
    auto const refused = peer::check(*alice_hello, *digest, *raw);
    std::string const outcome = refused ? std::string("accepted") : refused.error().message();
    std::printf("not normalized: %s\n", outcome.c_str());

    auto const alice_key = alice->session_key(*bob_hello, *digest);
    auto const bob_key = bob->session_key(*alice_hello, *digest);
    if (!alice_key || !bob_key || !crypto::equal(alice_key->bytes(), bob_key->bytes())) {
        std::printf("failed\n");
        return 1;
    }
    std::printf("session keys agree\n");
    // A real program never prints a key; this one does to show the fixed value.
    print("session key", alice_key->bytes());
    return 0;
}

// end::program[]
