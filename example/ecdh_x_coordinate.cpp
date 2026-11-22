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
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <type_traits>

namespace crypto = webcpp::crypto;
namespace secp256k1 = webcpp::crypto::curves::secp256k1;
namespace hash2 = boost::hash2;

namespace {

// Overwrites a secret through a volatile pointer, which the optimiser cannot drop as a dead
// store: crypto wipes its own copies of keys this way, and the program wipes its own.
void wipe(std::span<std::byte> secret) {
    std::byte volatile* const bytes = secret.data();
    for (std::size_t i = 0; i < secret.size(); ++i) {
        bytes[i] = std::byte{0};
    }
}

// Wipes an object of key-derived state, such as an HMAC whose inner and outer states hold the
// key: its bytes are all it is, so overwriting them leaves nothing of the key.
template <class T>
void wipe_object(T& object) {
    static_assert(std::is_trivially_copyable_v<T>);
    wipe(std::as_writable_bytes(std::span(&object, 1)));
}

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
std::array<std::uint8_t, 32> conversation_key(crypto::secret<32> const& shared_x) {
    auto const salt = bytes_of("nip44-v2");
    hash2::hmac_sha2_256 extract(salt.data(), salt.size());
    extract.update(shared_x.bytes().data(), crypto::secret<32>::size());
    auto digest = extract.result();
    wipe_object(extract);
    std::array<std::uint8_t, 32> key{};
    std::span<std::uint8_t const> const digest_bytes(digest.data(), digest.size());
    std::ranges::copy(digest_bytes, key.begin());
    wipe(std::as_writable_bytes(std::span(digest.data(), digest.size())));
    return key;
}

boost::system::result<secp256k1::keypair> from_secret(std::uint8_t fill) {
    std::array<std::uint8_t, 32> secret{};
    secret.fill(fill);
    auto made = secp256k1::keypair::make(secret);
    // The key pair keeps its own copy, which it wipes; this one goes now.
    wipe(std::as_writable_bytes(std::span(secret)));
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
    if (!alice_x || !bob_x || !crypto::equal(alice_x->bytes(), bob_x->bytes())) {
        return 1;
    }
    std::printf("shared x coordinates match\n");

    // A real program never prints a shared secret; this one does to show the fixed value.
    print_hex("x: ", alice_x->bytes());
    auto key = conversation_key(*alice_x);
    print_hex("conversation key (what a NIP-44 library derives): ", key);
    wipe(std::as_writable_bytes(std::span(key)));
    return 0;
}

// end::program[]
