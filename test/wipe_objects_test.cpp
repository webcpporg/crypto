// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A destroyed key schedule is zero (spec section 2.11): an object of the backend's keyed type is
// made in storage of the test's own, with a key of non-zero bytes, and the bytes of its key
// state are read through a volatile pointer after its destructor, as the source of a move
// construction and as the source of a move assignment. Each read is preceded by the same read
// before, which finds non-zero bytes, so that no check is vacuous. The program is built at -O2
// (the Jamfile's <optimization>speed), where a store the optimiser may drop is the case.
//
// One source, one backend per program: WEBCPP_TEST_WIPE_BEARSSL, WEBCPP_TEST_WIPE_CTAES,
// WEBCPP_TEST_WIPE_SECP256K1 (the key pair, and MuSig2's secret nonce),
// WEBCPP_TEST_WIPE_OPENSSL or WEBCPP_TEST_WIPE_SODIUM.

#include <webcpp/test/exit_status.hpp>

#ifdef WEBCPP_TEST_WIPE_BEARSSL
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#elif defined(WEBCPP_TEST_WIPE_CTAES)
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#elif defined(WEBCPP_TEST_WIPE_SECP256K1)
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#elif defined(WEBCPP_TEST_WIPE_OPENSSL)
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#elif defined(WEBCPP_TEST_WIPE_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#else
#error "name a backend: WEBCPP_TEST_WIPE_BEARSSL, _CTAES, _SECP256K1, _OPENSSL or _SODIUM"
#endif

#include "require.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;

// The storage of one object, aligned for it.
template <class T>
struct slot {
    alignas(T) std::array<std::byte, sizeof(T)> bytes{};
};

// The bytes of the key state in an object: where they start, and how many.
struct region {
    std::size_t offset;
    std::size_t size;
};

// Whether any byte of the region is not zero, read through a volatile pointer so that the read
// is neither merged with a store nor dropped. The pointer is itself read back from a volatile
// object, so that the optimiser cannot tell which storage it reads: after a destructor, GCC
// takes the bytes of the destroyed object for indeterminate (its end-of-lifetime clobber, which
// -Wuninitialized reports at -O3) and could fold the read. The stores the destructor made, or
// dropped, are what the read finds.
template <class T>
bool any_set(slot<T> const& storage, region where) {
    auto const* const volatile opaque =
        reinterpret_cast<unsigned char const volatile*>(storage.bytes.data());
    unsigned char const volatile* const bytes = opaque;
    for (std::size_t i = where.offset; i < where.offset + where.size; ++i) {
        if (bytes[i] != 0) {
            return true;
        }
    }
    return false;
}

// An object in its storage, which this destroys at the end of its scope unless it is released.
template <class T>
class placed {
public:
    placed(slot<T>& storage, T&& value) : object_(new (storage.bytes.data()) T(std::move(value))) {}

    placed(placed const&) = delete;
    placed& operator=(placed const&) = delete;

    ~placed() { destroy(); }

    T& operator*() const { return *object_; }

    void destroy() {
        if (object_ != nullptr) {
            std::destroy_at(std::exchange(object_, nullptr));
        }
    }

private:
    T* object_;
};

// A peer's X25519 public key: RFC 7748 section 6.1's, Bob's.
constexpr std::array<std::uint8_t, 32> rfc7748_peer_key{
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
};

// A keyed object of the type under test, from a key of non-zero bytes; a box's from that secret
// key and a peer's public key.
template <class T>
T keyed(std::uint8_t first) {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(first + i);
    }
    if constexpr (requires { T::make(key, rfc7748_peer_key); }) {
        auto made = T::make(key, rfc7748_peer_key);
        webcpp::test::require(made.has_value());
        return std::move(*made);
    } else {
        auto made = T::make(key);
        webcpp::test::require(made.has_value());
        return std::move(*made);
    }
}

// The three ways a keyed object stops holding its key; `make` makes one from a first byte.
template <class T>
void check_wiped(region where, T (*make)(std::uint8_t) = &keyed<T>) {
    {
        // The destructor.
        slot<T> storage;
        placed<T> object(storage, make(1));
        BOOST_TEST(any_set(storage, where));
        object.destroy();
        BOOST_TEST(!any_set(storage, where));
    }
    {
        // The source of a move construction: the destination holds the key now, the source
        // none.
        slot<T> from_storage;
        slot<T> to_storage;
        placed<T> from(from_storage, make(1));
        BOOST_TEST(any_set(from_storage, where));
        placed<T> to(to_storage, std::move(*from));
        BOOST_TEST(!any_set(from_storage, where));
        BOOST_TEST(any_set(to_storage, where));
        to.destroy();
        BOOST_TEST(!any_set(to_storage, where));
        from.destroy();
        BOOST_TEST(!any_set(from_storage, where));
    }
    {
        // The source of a move assignment, and the destination's own old key, which it
        // gives up first.
        slot<T> from_storage;
        slot<T> to_storage;
        placed<T> from(from_storage, make(1));
        placed<T> to(to_storage, make(100));
        BOOST_TEST(any_set(from_storage, where));
        BOOST_TEST(any_set(to_storage, where));
        *to = std::move(*from);
        BOOST_TEST(!any_set(from_storage, where));
        BOOST_TEST(any_set(to_storage, where));
        to.destroy();
        BOOST_TEST(!any_set(to_storage, where));
        from.destroy();
        BOOST_TEST(!any_set(from_storage, where));
    }
}

#ifdef WEBCPP_TEST_WIPE_SODIUM
// The key libsodium's AEAD or secret box of the family Family keeps in the object, first.
template <class Family>
constexpr region aead_key{
    .offset = 0,
    .size = sizeof(crypto::detail::aead_state<Family, crypto::backends::sodium>),
};

// The key libsodium's box of the family Family agreed and keeps in the object, first.
template <class Family>
constexpr region box_key{
    .offset = 0,
    .size = sizeof(crypto::detail::box_state<Family, crypto::backends::sodium>),
};
#endif

#ifdef WEBCPP_TEST_WIPE_SECP256K1
// A MuSig2 secret nonce of the key pair of `first`, its key aggregated alone.
crypto::curves::secp256k1::musig::secret_nonce nonce_of(std::uint8_t first) {
    namespace secp = crypto::curves::secp256k1;
    auto const signer = keyed<secp::keypair>(first);
    auto const signer_key = signer.public_key();
    webcpp::test::require(signer_key.has_value());
    std::array<secp::public_key, 1> const keys{*signer_key};
    std::array<std::byte, secp::musig::workspace_size(1)> space{};
    auto const key = secp::musig::key_aggregate(keys, space);
    webcpp::test::require(key.has_value());
    auto made = secp::musig::nonce_gen(signer, *key);
    webcpp::test::require(made.has_value());
    return std::move(made->secret_part);
}
#endif

}  // namespace

int main() {
#ifdef WEBCPP_TEST_WIPE_BEARSSL
    // The state is gcm's first member: the schedule and the context of BearSSL.
    using type = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>;
    check_wiped<type>(
        {.offset = 0, .size = sizeof(crypto::detail::gcm_state<crypto::backends::bearssl, 32>)});
    // ChaCha20-Poly1305's state is aead's first member: the key itself.
    using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>;
    check_wiped<chacha>({
        .offset = 0,
        .size = sizeof(crypto::detail::aead_state<crypto::families::chacha20_poly1305,
                                                  crypto::backends::bearssl>),
    });
#elif defined(WEBCPP_TEST_WIPE_CTAES)
    // The state is the block cipher's first member: the expanded schedule.
    using type = crypto::ciphers::aes256<crypto::backends::ctaes>;
    check_wiped<type>(
        {.offset = 0, .size = sizeof(crypto::detail::block_state<crypto::backends::ctaes, 32>)});
#elif defined(WEBCPP_TEST_WIPE_SECP256K1)
    // After the context's pointer and the resource's, the key pair of libsecp256k1, which holds
    // the secret key. The context's pointer is not secret: release() stores null to it, a store
    // an optimiser may drop at the end of an object's life, which is why the region starts
    // after it. The resource's pointer stays too, so the layout is part of what this checks (a
    // wrong offset fails the zero reads).
    using type = crypto::curves::secp256k1::keypair;
    static_assert(sizeof(type) >= (2 * sizeof(void*)) + sizeof(secp256k1_keypair));
    check_wiped<type>({.offset = 2 * sizeof(void*), .size = sizeof(secp256k1_keypair)});
    // A MuSig2 secret nonce: libsecp256k1's secnonce comes first, its two secret scalars and the
    // signer's key, zero after the destructor and in the source of a move.
    check_wiped<crypto::curves::secp256k1::musig::secret_nonce>(
        {.offset = 0, .size = sizeof(secp256k1_musig_secnonce)}, &nonce_of);
#elif defined(WEBCPP_TEST_WIPE_OPENSSL)
    // OpenSSL cleanses the expanded key in EVP_CIPHER_CTX_free (its own, not webcpp's); what
    // webcpp holds is the pointers, which are null once the key is given up.
    check_wiped<crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::openssl>>>(
        {.offset = 0, .size = sizeof(crypto::detail::gcm_state<crypto::backends::openssl, 32>)});
    check_wiped<crypto::ciphers::aes256<crypto::backends::openssl>>(
        {.offset = 0, .size = sizeof(crypto::detail::block_state<crypto::backends::openssl, 32>)});
    check_wiped<crypto::ciphers::chacha20_poly1305<crypto::backends::openssl>>({
        .offset = 0,
        .size = sizeof(crypto::detail::aead_state<crypto::families::chacha20_poly1305,
                                                  crypto::backends::openssl>),
    });
#elif defined(WEBCPP_TEST_WIPE_SODIUM)
    // libsodium takes the key per call, so webcpp keeps it: an AEAD's or a secret box's state
    // is aead's first member, the key; a box's is basic_box's first member, the key beforenm
    // agreed.
    using crypto::backends::sodium;
    namespace families = crypto::families;
    check_wiped<crypto::ciphers::chacha20_poly1305<sodium>>(aead_key<families::chacha20_poly1305>);
    check_wiped<crypto::ciphers::chacha20_poly1305_original<sodium>>(
        aead_key<families::chacha20_poly1305_original>);
    check_wiped<crypto::ciphers::xchacha20_poly1305<sodium>>(
        aead_key<families::xchacha20_poly1305>);
    check_wiped<crypto::ciphers::secretbox<sodium>>(aead_key<families::secretbox_xsalsa20poly1305>);
    check_wiped<crypto::ciphers::secretbox_xchacha20poly1305<sodium>>(
        aead_key<families::secretbox_xchacha20poly1305>);
    check_wiped<crypto::hybrid::basic_box<families::box_xsalsa20poly1305, sodium>>(
        box_key<families::box_xsalsa20poly1305>);
    check_wiped<crypto::hybrid::basic_box<families::box_xchacha20poly1305, sodium>>(
        box_key<families::box_xchacha20poly1305>);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
