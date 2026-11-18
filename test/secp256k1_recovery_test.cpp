// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// secp256k1's recoverable ECDSA signatures and hedged ECDSA: 64 seeded key pairs and hashes,
// each recovered to its key; libsecp256k1's own recovery edge cases; the refusals of an id
// above 3, of an r or an s out of range, and of a moved-from key pair; the hedged signature,
// equal to libsecp256k1's own with the same extra entropy and different from the unhedged one.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/secp256k1_checks.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <type_traits>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;
namespace test = webcpp::test;

namespace {

using hash_bytes = std::array<std::uint8_t, 32>;
using recoverable = std::array<std::uint8_t, secp::recoverable_signature_size>;

static_assert(secp::recoverable_signature_size == 65);
static_assert(std::is_same_v<decltype(secp::recover(std::declval<recoverable const&>(),
                                                    std::declval<hash_bytes const&>())),
                             boost::system::result<secp::public_key>>);

// A key pair from the generator: a secret make refuses is drawn again.
secp::keypair draw(std::mt19937_64& generator, hash_bytes& secret) {
    for (;;) {
        for (auto& octet : secret) {
            octet = static_cast<std::uint8_t>(generator());
        }
        auto made = secp::keypair::make(secret);
        if (made) {
            return std::move(*made);
        }
        BOOST_TEST(made.error() == crypto::error::invalid_secret_key);
    }
}

hash_bytes draw_hash(std::mt19937_64& generator) {
    hash_bytes hash{};
    for (auto& octet : hash) {
        octet = static_cast<std::uint8_t>(generator());
    }
    return hash;
}

// The key pair's public key, parsed.
secp::public_key key_of(secp::keypair const& key) {
    return *secp::parse_public_key(*key.public_key());
}

bool refused_as_signature(boost::system::result<secp::public_key> const& recovered) {
    return recovered.has_error() && recovered.error() == crypto::error::invalid_signature;
}

// An id of 4, 5 or 255 is refused without reaching libsecp256k1's illegal callback.
void refuses_bad_ids(recoverable const& signature, hash_bytes const& hash) {
    for (std::uint8_t const id : {4, 5, 255}) {
        auto bad_id = signature;
        bad_id[64] = id;
        BOOST_TEST(refused_as_signature(secp::recover(bad_id, hash)));
    }
}

// Another hash finds another key or none; true when it found a key.
bool another_hash_finds_another_key(secp::keypair const& key, recoverable const& signature,
                                    hash_bytes const& hash) {
    auto other_hash = hash;
    other_hash[0] ^= 0x80U;
    auto const other = secp::recover(signature, other_hash);
    if (!other) {
        BOOST_TEST(other.error() == crypto::error::invalid_signature);
        return false;
    }
    BOOST_TEST(*other != key_of(key));
    return true;
}

// One round: the signature recovers the key pair's key, the id is 0 to 3, and the first 64
// bytes are sign_ecdsa's; true when another hash found another key.
bool round_trip(std::mt19937_64& generator) {
    hash_bytes secret{};
    auto const key = draw(generator, secret);
    auto const hash = draw_hash(generator);
    auto const signature = key.sign_recoverable(hash);
    auto const plain = key.sign_ecdsa(hash);
    if (!BOOST_TEST(signature && plain)) {
        return false;
    }
    BOOST_TEST((*signature)[64] <= 3);
    BOOST_TEST(std::ranges::equal(std::span(*signature).first(64), *plain));
    auto const recovered = secp::recover(*signature, hash);
    if (BOOST_TEST(recovered.has_value())) {
        BOOST_TEST(*recovered == key_of(key));
    }
    bool const found = another_hash_finds_another_key(key, *signature, hash);
    refuses_bad_ids(*signature, hash);
    return found;
}

// 64 key pairs and hashes, each through round_trip.
void round_trips() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x2ec0e7ab1eULL);
    int other_keys = 0;
    for (int round = 0; round < 64; ++round) {
        if (round_trip(generator)) {
            ++other_keys;
        }
    }
    BOOST_TEST(other_keys > 0);
}

// From libsecp256k1's src/modules/recovery/tests_impl.h, test_ecdsa_recovery_edge_cases
// (v0.8.0, MIT; Copyright (c) 2013-2015 Pieter Wuille): its message, and a signature made with
// the secret key 0 and a fixed nonce, which recovers a key with id 1 alone.
constexpr hash_bytes edge_message = {
    'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'v', 'e', 'r', 'y', ' ', 's',
    'e', 'c', 'r', 'e', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e', '.', '.', '.',
};
constexpr std::array<std::uint8_t, 64> edge_signature = {
    0x67, 0xCB, 0x28, 0x5F, 0x9C, 0xD1, 0x94, 0xE8, 0x40, 0xD6, 0x29, 0x39, 0x7A, 0xF5, 0x56, 0x96,
    0x62, 0xFD, 0xE4, 0x46, 0x49, 0x99, 0x59, 0x63, 0x17, 0x9A, 0x7D, 0xD1, 0x7B, 0xD2, 0x35, 0x32,
    0x4B, 0x1B, 0x7D, 0xF3, 0x4C, 0xE1, 0xF6, 0x8E, 0x69, 0x4F, 0xF6, 0xF1, 0x1A, 0xC7, 0x51, 0xDD,
    0x7D, 0xD7, 0x3E, 0x38, 0x7E, 0xE4, 0xFC, 0x86, 0x6E, 0x1B, 0xE8, 0xEC, 0xC7, 0xDD, 0x95, 0x57,
};

// (r, s) as two small numbers, then the id.
recoverable small_signature(std::uint8_t r, std::uint8_t s, std::uint8_t id) {
    recoverable signature{};
    signature[31] = r;
    signature[63] = s;
    signature[64] = id;
    return signature;
}

// The fixed signature recovers a key with id 1 alone.
void edge_signature_ids() {
    for (std::uint8_t id = 0; id < 4; ++id) {
        recoverable signature{};
        std::ranges::copy(edge_signature, signature.begin());
        signature[64] = id;
        auto const recovered = secp::recover(signature, edge_message);
        if (id == 1) {
            BOOST_TEST(recovered.has_value());
        } else {
            BOOST_TEST(refused_as_signature(recovered));
        }
    }
}

// (r, s) = (4, 4) recovers a key with each id, and verifies under each; (1, 1) recovers with id
// 0, and verifies.
void small_signatures_recover() {
    for (std::uint8_t id = 0; id < 4; ++id) {
        auto const signature = small_signature(4, 4, id);
        auto const recovered = secp::recover(signature, edge_message);
        if (!BOOST_TEST(recovered.has_value())) {
            continue;
        }
        auto const encoded = secp::serialize_public_key(*recovered);
        BOOST_TEST(secp::verify_ecdsa(std::span(signature).first<64>(), edge_message, encoded)
                       .has_value());
    }

    auto const one_one = small_signature(1, 1, 0);
    auto const recovered = secp::recover(one_one, edge_message);
    if (BOOST_TEST(recovered.has_value())) {
        BOOST_TEST(secp::verify_ecdsa(std::span(one_one).first<64>(), edge_message,
                                      secp::serialize_public_key(*recovered))
                       .has_value());
    }
}

// r = 0 or s = 0: no key; r or s equal to the group order n, or above it: refused by the parser.
void out_of_range_signatures() {
    BOOST_TEST(refused_as_signature(secp::recover(small_signature(0, 1, 0), edge_message)));
    BOOST_TEST(refused_as_signature(secp::recover(small_signature(1, 0, 0), edge_message)));
    BOOST_TEST(refused_as_signature(secp::recover(small_signature(0, 0, 0), edge_message)));

    auto const order =
        test::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    auto r_is_n = small_signature(0, 4, 0);
    std::ranges::copy(order, r_is_n.begin());
    BOOST_TEST(refused_as_signature(secp::recover(r_is_n, edge_message)));
    auto s_is_n = small_signature(4, 0, 0);
    std::ranges::copy(order, s_is_n.begin() + 32);
    BOOST_TEST(refused_as_signature(secp::recover(s_is_n, edge_message)));
    recoverable all_ones{};
    all_ones.fill(0xff);
    all_ones[64] = 0;
    BOOST_TEST(refused_as_signature(secp::recover(all_ones, edge_message)));
}

void edge_cases() {
    edge_signature_ids();
    small_signatures_recover();
    out_of_range_signatures();
}

// libsecp256k1's own ECDSA signature with RFC 6979's nonce and the given ndata, through its C
// API, on a context of its own.
std::array<std::uint8_t, 64> reference_signature(secp256k1_context const* context,
                                                 hash_bytes const& secret, hash_bytes const& hash,
                                                 hash_bytes const* extra) {
    secp256k1_ecdsa_signature signature{};
    BOOST_TEST_EQ(secp256k1_ecdsa_sign(context, &signature, hash.data(), secret.data(), nullptr,
                                       extra == nullptr ? nullptr : extra->data()),
                  1);
    std::array<std::uint8_t, 64> compact{};
    secp256k1_ecdsa_signature_serialize_compact(context, compact.data(), &signature);
    return compact;
}

// One round of the hedged form against libsecp256k1's own signatures.
void hedged_round(secp256k1_context const* context, std::mt19937_64& generator) {
    hash_bytes secret{};
    auto const key = draw(generator, secret);
    auto const hash = draw_hash(generator);
    auto const first_entropy = draw_hash(generator);
    auto second_entropy = first_entropy;
    second_entropy[31] ^= 0x01U;
    hash_bytes const zero{};

    auto const first = key.sign_ecdsa(hash, first_entropy);
    auto const second = key.sign_ecdsa(hash, second_entropy);
    auto const zeroed = key.sign_ecdsa(hash, zero);
    auto const plain = key.sign_ecdsa(hash);
    if (!BOOST_TEST(first && second && zeroed && plain)) {
        return;
    }
    BOOST_TEST(*first != *second);
    BOOST_TEST(*zeroed != *plain);
    BOOST_TEST(*first != *plain);
    auto const public_key = *key.public_key();
    BOOST_TEST(secp::verify_ecdsa(*first, hash, public_key).has_value());
    BOOST_TEST(secp::verify_ecdsa(*second, hash, public_key).has_value());
    BOOST_TEST(secp::verify_ecdsa(*zeroed, hash, public_key).has_value());
    BOOST_TEST(*first == reference_signature(context, secret, hash, &first_entropy));
    BOOST_TEST(*second == reference_signature(context, secret, hash, &second_entropy));
    BOOST_TEST(*zeroed == reference_signature(context, secret, hash, &zero));
    BOOST_TEST(*plain == reference_signature(context, secret, hash, nullptr));
    // Hedged twice with the same entropy, the signature is the same: the hedging is
    // deterministic given its input.
    BOOST_TEST(key.sign_ecdsa(hash, first_entropy).value() == *first);
}

// The hedged form: different entropy gives different signatures, both valid, each libsecp256k1's
// own for that entropy; 32 zero bytes are mixed in too.
void hedged() {
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    secp256k1_context* const context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!BOOST_TEST(context != nullptr)) {
        return;
    }
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp): reproducible
    std::mt19937_64 generator(0x4ed6edULL);
    for (int round = 0; round < 16; ++round) {
        hedged_round(context, generator);
    }
    secp256k1_context_destroy(context);
}

// A moved-from key pair answers invalid_state from the new members, as from every other.
// NOLINTBEGIN(bugprone-use-after-move)
void moved_from() {
    auto made = secp::keypair::make(std::array<std::uint8_t, 32>{7});
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    secp::keypair source = std::move(*made);
    secp::keypair const target = std::move(source);
    hash_bytes const hash{};
    BOOST_TEST(source.sign_recoverable(hash).error() == crypto::error::invalid_state);
    BOOST_TEST(source.sign_ecdsa(hash, hash).error() == crypto::error::invalid_state);
    BOOST_TEST(source.public_key_uncompressed().error() == crypto::error::invalid_state);
    test::expect_empty_keypair(source);
    BOOST_TEST(target.sign_recoverable(hash).has_value());
}

// NOLINTEND(bugprone-use-after-move)

}  // namespace

int main() {
    round_trips();
    edge_cases();
    hedged();
    moved_from();
    return webcpp::test::exit_status(boost::report_errors());
}
