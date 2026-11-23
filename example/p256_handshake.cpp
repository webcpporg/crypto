// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A signed handshake between two peers on P-256, as a browser's WebCrypto can take part in it:
// each peer keeps a long-lived identity key pair as its scalar, and makes a fresh key pair for
// the session; each sends its two public keys raw, signs the SHA-256 digest of the handshake's
// bytes with its identity (sign gives low S), and checks the other's signature, low S first, since
// another implementation, a browser's WebCrypto among them, may sign high S; both derive the
// session key from ECDH's x through HKDF-SHA-256. Every scalar is fixed, so that the output is;
// a real program draws its key pairs with keypair::generate(). What is signed, when, and the
// low-S rule are a protocol's: this one is an example, not webcpp::trystero's.
// tag::program[]
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/hash/digest.hpp>
#include <webcpp/hash/hkdf.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
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
    return p256::keypair::from_secret(scalar);
}

// What a peer sends: its identity's public key and its session key pair's, raw, as WebCrypto's
// exportKey("raw") writes them.
struct hello {
    std::array<std::uint8_t, p256::public_key_size> identity{};
    std::array<std::uint8_t, p256::public_key_size> session{};
};

// What the receiver concludes of a peer's signature.
enum class verdict : std::uint8_t {
    ok,
    bad_identity,
    high_s,
    bad_signature,
};

// The verdict, as the program prints it.
char const* text_of(verdict found) {
    switch (found) {
        case verdict::ok: return "ok";
        case verdict::bad_identity: return "refused: the identity key is not a P-256 point";
        case verdict::high_s: return "refused: high S, against the protocol's low-S rule";
        case verdict::bad_signature: return "refused: the signature does not verify";
    }
    return "refused";
}

// The high-S form of a low-S signature, r || (n - s): as another implementation, a browser's
// WebCrypto among them, may sign the same digest.
std::array<std::uint8_t, p256::signature_size> high_s_form(
    std::span<std::uint8_t const, p256::signature_size> signature) {
    // FIPS 186-5 / SEC 2: P-256's group order n.
    constexpr std::array<std::uint8_t, 32> order{
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
        0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    std::array<std::uint8_t, p256::signature_size> high{};
    std::ranges::copy(signature, high.begin());
    unsigned borrow = 0;
    for (std::size_t i = order.size(); i-- > 0;) {
        unsigned const difference =
            static_cast<unsigned>(order[i]) - signature[order.size() + i] - borrow;
        high[order.size() + i] = static_cast<std::uint8_t>(difference);
        borrow = (difference >> 8U) & 1U;
    }
    return high;
}

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
    // Signs the transcript's digest with the identity; sign gives the low-S form the protocol
    // requires.
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, p256::signature_size>> sign(
        std::span<std::uint8_t const, p256::digest_size> digest) const {
        return identity.sign(crypto::ecdsa_sha256, crypto::prehashed{digest});
    }

    // end::sign[]

    // tag::receive[]
    // Checks the other peer's signature of the transcript: low S first, as the protocol requires
    // (crypto::verify accepts both forms, as WebCrypto does), then the signature itself, with the
    // identity key the peer sent, made into a public_key. A real protocol also checks that this
    // identity is the one it expects.
    static verdict check(hello const& other,
                         std::span<std::uint8_t const, p256::digest_size> digest,
                         std::span<std::uint8_t const, p256::signature_size> signature) {
        auto const identity_key = p256::public_key::from_bytes(other.identity);
        if (!identity_key) {
            return verdict::bad_identity;
        }
        if (!p256::is_low_s(signature)) {
            return verdict::high_s;
        }
        if (!crypto::verify(crypto::ecdsa_sha256, signature, crypto::prehashed{digest},
                            *identity_key)) {
            return verdict::bad_signature;
        }
        return verdict::ok;
    }

    // end::receive[]

    // tag::session[]
    // The session key: ECDH's x of the two session key pairs, through HKDF-SHA-256 with the
    // transcript's digest as the salt, so that the key is bound to this handshake.
    [[nodiscard]] boost::system::result<crypto::secret<32>> session_key(
        hello const& other, std::span<std::uint8_t const, p256::digest_size> digest) const {
        auto const other_key = p256::public_key::from_bytes(other.session);
        if (!other_key) {
            return other_key.error();
        }
        auto const x = session.agree(*other_key);
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
    auto const kept = first ? first->secret() : first.error();
    if (!kept) {
        return kept.error();
    }
    auto identity = p256::keypair::from_secret(kept->bytes());
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
    std::printf("bob checks alice: %s; alice checks bob: %s\n",
                text_of(peer::check(*alice_hello, *digest, *alice_signature)),
                text_of(peer::check(*bob_hello, *digest, *bob_signature)));

    // Alice's signature with one bit of s flipped on the way: refused by the verification.
    auto tampered = *alice_signature;
    tampered[40] ^= 0x01U;
    std::printf("tampered: %s\n", text_of(peer::check(*alice_hello, *digest, tampered)));

    // The same digest signed by another implementation in the high-S form: refused by the
    // protocol's rule before it is verified, though crypto::verify alone accepts it.
    auto const high = high_s_form(*alice_signature);
    auto const alice_identity = p256::public_key::from_bytes(alice_hello->identity);
    bool const verifies_alone =
        alice_identity &&
        crypto::verify(crypto::ecdsa_sha256, high, crypto::prehashed{*digest}, *alice_identity);
    std::printf("high S: %s; crypto::verify alone: %s\n",
                text_of(peer::check(*alice_hello, *digest, high)),
                verifies_alone ? "verified" : "refused");

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
