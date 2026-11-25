// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two key pairs agree on the shared point's raw x coordinate with agree, the form Nostr's
// encrypted messages (NIP-44) take, then derive from it what a NIP-44 library would: the
// conversation key, HKDF-extract with the salt "nip44-v2". The x coordinate is not a key; the
// derivation that makes one is the protocol's, and belongs to a domain library.
// tag::program[]
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/secure/erase_secret.hpp>
#include <webcpp/secure/secret.hpp>

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>

namespace secure = webcpp::secure;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace hash2 = boost::hash2;

namespace {

std::span<std::uint8_t const> bytes_of(std::string_view text) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return {reinterpret_cast<std::uint8_t const*>(text.data()), text.size()};
}

void print_hex(char const* label, std::span<std::uint8_t const> bytes) {
    std::printf("%s", label);
    for (std::uint8_t const octet : bytes) {
        std::printf("%02x", static_cast<unsigned>(octet));
    }
    std::printf("\n");
}

// NIP-44's conversation key: HKDF-extract (RFC 5869), an HMAC-SHA-256 keyed with the salt
// "nip44-v2" over the shared x coordinate. A NIP-44 library computes it; the message keys,
// the padding and the payload's format that follow are the protocol's too.
std::array<std::uint8_t, 32> conversation_key(secure::secret<32> const& shared_x) {
    auto const salt = bytes_of("nip44-v2");
    hash2::hmac_sha2_256 extract(salt.data(), salt.size());
    extract.update(shared_x.bytes().data(), secure::secret<32>::size());
    auto digest = extract.result();
    secure::erase_secret(std::span(&extract, 1));
    std::array<std::uint8_t, 32> key{};
    std::span<std::uint8_t const> const digest_bytes(digest.data(), digest.size());
    std::ranges::copy(digest_bytes, key.begin());
    secure::erase_secret(std::span(digest.data(), digest.size()));
    return key;
}

boost::system::result<secp256k1::keypair> from_secret(std::uint8_t fill) {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(fill);
    auto made = secp256k1::keypair::from_secret(secret);
    // The key pair keeps its own copy, which it wipes; this one goes now.
    secure::erase_secret(secret);
    return made;
}

}  // namespace

int main() {
    // Fixed secrets, so that the output is fixed. A real program draws its secret keys from
    // random_device, as wallet_key.cpp does.
    auto const alice = from_secret(0x11);
    auto const bob = from_secret(0x22);
    if (!alice || !bob) {
        return 1;
    }
    auto const alice_public = alice->public_key();
    auto const bob_public = bob->public_key();
    if (!alice_public || !bob_public) {
        return 1;
    }
    // Each side combines its secret key with the other's public key: the same x coordinate,
    // a secret<32> that wipes itself.
    auto const alice_x = alice->agree(*bob_public);
    auto const bob_x = bob->agree(*alice_public);
    if (!alice_x || !bob_x || !secure::constant_time_equal(alice_x->bytes(), bob_x->bytes())) {
        return 1;
    }
    std::printf("shared x coordinates match\n");

    // A real program never prints a shared secret; this one does to show the fixed value.
    print_hex("x: ", alice_x->bytes());
    auto key = conversation_key(*alice_x);
    print_hex("conversation key (what a NIP-44 library derives): ", key);
    secure::erase_secret(key);
    return 0;
}

// end::program[]
