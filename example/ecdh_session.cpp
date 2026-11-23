// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two peers agree on a shared secret with ECDH, derive a session key from it with HKDF-SHA-256
// and talk over AES-256-GCM. The raw ECDH output is not a key: HKDF turns it into one and ties
// it to this application with a context string.
// tag::program[]
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>
#include <webcpp/crypto/secret.hpp>

#include <boost/hash2/sha2.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

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

template <std::size_t N>
std::array<std::uint8_t, N> from_hex(std::string_view text) {
    std::array<std::uint8_t, N> out{};
    auto const nibble = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) * 16) + nibble(text[(2 * i) + 1]));
    }
    return out;
}

// tag::hkdf[]
// HKDF-SHA-256 (RFC 5869): extract concentrates the input's entropy into a pseudorandom key,
// expand stretches it into as many bytes as asked, each block bound to the info string.
template <std::size_t Length>
std::array<std::uint8_t, Length> hkdf_sha256(std::span<std::uint8_t const> input,
                                             std::span<std::uint8_t const> salt,
                                             std::span<std::uint8_t const> info) {
    static_assert(Length <= std::size_t{255} * 32);
    // An empty salt stands for a block of zeros.
    std::array<std::uint8_t, 32> const zeros{};
    if (salt.empty()) {
        salt = zeros;
    }
    hash2::hmac_sha2_256 extract(salt.data(), salt.size());
    extract.update(input.data(), input.size());
    auto prk = extract.result();
    wipe_object(extract);

    std::array<std::uint8_t, Length> out{};
    std::array<std::uint8_t, 32> previous{};
    std::size_t previous_size = 0;
    std::size_t offset = 0;
    for (std::uint8_t counter = 1; offset < Length; ++counter) {
        hash2::hmac_sha2_256 expand(prk.data(), prk.size());
        expand.update(previous.data(), previous_size);
        expand.update(info.data(), info.size());
        expand.update(&counter, 1);
        auto block = expand.result();
        wipe_object(expand);
        std::copy_n(block.data(), block.size(), previous.begin());
        wipe(std::as_writable_bytes(std::span(block)));
        previous_size = previous.size();
        std::size_t const taken = std::min(previous.size(), Length - offset);
        std::copy_n(previous.begin(), taken, out.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += taken;
    }
    // The pseudorandom key and the last block are as secret as the input, and so are the HMACs
    // keyed with them, wiped above: wipe them.
    wipe(std::as_writable_bytes(std::span(prk)));
    wipe(std::as_writable_bytes(std::span(previous)));
    return out;
}

// end::hkdf[]

boost::system::result<secp256k1::keypair> generate_key() {
    crypto::random_device device;
    std::array<std::uint8_t, 32> secret{};
    for (;;) {
        auto const filled = device.fill(secret);
        if (!filled) {
            return filled.error();
        }
        auto key = secp256k1::keypair::from_secret(secret);
        if (key || key.error() != crypto::error::invalid_secret_key) {
            // The key pair keeps its own copy, which it wipes; this one goes now.
            wipe(std::as_writable_bytes(std::span(secret)));
            return key;
        }
    }
}

// Both sides derive their session key the same way. The shared secret wipes itself when it
// goes out of scope; the key derived from it is the program's to wipe.
boost::system::result<crypto::ciphers::aes256_gcm> session_cipher(
    crypto::secret<32> const& shared) {
    auto key = hkdf_sha256<32>(shared.bytes(), {}, bytes_of("example chat v1 session key"));
    auto cipher = crypto::ciphers::aes256_gcm::from_key(key);
    // The cipher keeps its own copy of the key, which it wipes; this one goes now.
    wipe(std::as_writable_bytes(std::span(key)));
    return cipher;
}

// Checks the function against the RFC's first test vector before it is trusted.
bool hkdf_is_correct() {
    std::array<std::uint8_t, 22> input{};
    input.fill(0x0b);
    auto const salt = from_hex<13>("000102030405060708090a0b0c");
    auto const info = from_hex<10>("f0f1f2f3f4f5f6f7f8f9");
    auto const expected = from_hex<42>(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    return crypto::constant_time_equal(hkdf_sha256<42>(input, salt, info), expected);
}

}  // namespace

int main() {
    if (!hkdf_is_correct()) {
        return 1;
    }
    std::printf("hkdf matches rfc 5869\n");

    // tag::agree[]
    auto alice = generate_key();
    auto bob = generate_key();
    if (!alice || !bob) {
        return 1;
    }
    // Each side sends its public key (its 33 compressed bytes) and keeps its secret.
    auto const alice_public = alice->public_key();
    auto const bob_public = bob->public_key();
    if (!alice_public || !bob_public) {
        return 1;
    }
    // The shared secrets live only in this block: each is a secret<32>, which wipes itself at
    // the block's end, as soon as the session ciphers are made from it.
    std::optional<crypto::ciphers::aes256_gcm> alice_cipher;
    std::optional<crypto::ciphers::aes256_gcm> bob_cipher;
    {
        auto const alice_shared = alice->agree_hashed(*bob_public);
        auto const bob_shared = bob->agree_hashed(*alice_public);
        if (!alice_shared || !bob_shared ||
            !crypto::constant_time_equal(alice_shared->bytes(), bob_shared->bytes())) {
            return 1;
        }
        std::printf("shared secrets match\n");
        auto alice_made = session_cipher(*alice_shared);
        auto bob_made = session_cipher(*bob_shared);
        if (!alice_made || !bob_made) {
            return 1;
        }
        alice_cipher.emplace(std::move(*alice_made));
        bob_cipher.emplace(std::move(*bob_made));
    }
    // end::agree[]

    std::array<std::uint8_t, 12> iv{};
    if (!crypto::random_device().fill(iv)) {
        return 1;
    }
    std::string_view const text = "hello bob";
    std::array<std::uint8_t, 9> message{};
    std::ranges::copy(text, message.begin());
    auto const tag = alice_cipher->seal(iv, {}, message);
    if (!tag || !bob_cipher->open(iv, {}, message, std::span<std::uint8_t const>(*tag))) {
        return 1;
    }
    std::printf("bob read: %.*s\n", static_cast<int>(message.size()),
                reinterpret_cast<char const*>(message.data()));
    return 0;
}

// end::program[]
