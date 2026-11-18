// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1 on libsecp256k1: BIP340 Schnorr and ECDSA signatures, hedged and recoverable, their
 verification and the recovery of a signer's key, and ECDH in three forms, each a secret; the
 parsed public key in its two SEC1 forms; ECDSA's DER and low-S forms, the tweak of an x-only
 key, and the workspace a function over many keys borrows.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the context's randomisation, its purpose
#include <webcpp/crypto/secret.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <memory_resource>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::crypto::curves::secp256k1 {

template <class Backend>
class basic_keypair;

class public_key;

}  // namespace webcpp::crypto::curves::secp256k1

namespace webcpp::crypto::detail {

/**
 * The one door of the module headers (those under `curves/secp256k1/`) into a key pair and a public
 * key: the key pair's context and `secp256k1_keypair`, whether it is keyed, and a public key's
 * point. It hands out nothing a caller of crypto could not already do through the key pair.
 */
struct secp256k1_access {
    /**
     * Whether a key pair holds a key: false moved from, or after a refused tweak.
     *
     * @param key_pair The key pair.
     * @return Whether it is keyed.
     */
    template <class Backend>
    [[nodiscard]] static bool keyed(
        curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept;

    /**
     * A key pair's randomised signing context, for the functions that multiply the generator.
     *
     * @param key_pair The key pair, keyed.
     * @return Its context; null moved from.
     */
    template <class Backend>
    [[nodiscard]] static secp256k1_context const* context(
        curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept;

    /**
     * A key pair's `secp256k1_keypair`, its secret and public key.
     *
     * @param key_pair The key pair, keyed.
     * @return Its `secp256k1_keypair`, wiped moved from.
     */
    template <class Backend>
    [[nodiscard]] static secp256k1_keypair const& pair(
        curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept;

    /**
     * A public key's point.
     *
     * @param key The public key.
     * @return Its `secp256k1_pubkey`.
     */
    [[nodiscard]] static secp256k1_pubkey const& point(
        curves::secp256k1::public_key const& key) noexcept;

    /**
     * A public key's point, to be written by the function that makes the key.
     *
     * @param key The public key.
     * @return Its `secp256k1_pubkey`.
     */
    [[nodiscard]] static secp256k1_pubkey& point(curves::secp256k1::public_key& key) noexcept;

    /**
     * A public key whose point is zero, not yet a key: the function that returns it writes its
     * point first, and returns an error instead where libsecp256k1 writes none.
     *
     * @return The unwritten key.
     */
    [[nodiscard]] static curves::secp256k1::public_key make_public_key() noexcept;

    /**
     * An object of a module header's opaque type (MuSig2's aggregate key, nonces, session and
     * partial signature), not yet written: the function that returns it writes its
     * libsecp256k1 struct first, and returns an error instead where libsecp256k1 writes none.
     *
     * @tparam Opaque The type, whose default constructor is private.
     * @return The unwritten object.
     */
    template <class Opaque>
    [[nodiscard]] static Opaque make_opaque() noexcept {
        return Opaque();
    }

    /**
     * What a module header's opaque type wraps, its private member `native_value_`: the
     * libsecp256k1 struct, or for a secret nonce the struct and what crypto keeps beside it.
     *
     * @tparam Opaque The type, `const` for a read.
     * @param object The object.
     * @return Its member, `const` when the object is.
     */
    template <class Opaque>
    [[nodiscard]] static auto& native(Opaque& object) noexcept {
        return object.native_value_;
    }
};

// NOLINTBEGIN(bugprone-signed-bitwise): libsecp256k1's macros shift a signed constant
/** The flags of a context that signs and verifies: none. */
inline constexpr unsigned secp256k1_context_flags = SECP256K1_CONTEXT_NONE;

/** The flag of the SEC1 compressed form. */
inline constexpr unsigned secp256k1_compressed = SECP256K1_EC_COMPRESSED;

/** The flag of the SEC1 uncompressed form. */
inline constexpr unsigned secp256k1_uncompressed = SECP256K1_EC_UNCOMPRESSED;
// NOLINTEND(bugprone-signed-bitwise)

/**
 * The error of a key pair whose context could not be randomised: every failure of the
 * generator is `entropy_unavailable`, the library's one word for it.
 *
 * Tip: the system's generator answers `errc::not_supported` where there is none (an
 * Emscripten audio worklet); a key pair's caller handles one error for both.
 */
inline boost::system::error_code secp256k1_seed_error(
    boost::system::error_code /*generator*/) noexcept {
    return error::entropy_unavailable;
}

/**
 * Secret bytes out of a key pair, its secret key or its context's seed, wiped when the scope
 * ends on every path, a failure's or an exception's included.
 */
struct secp256k1_secret {
    /** The secret bytes. */
    std::array<unsigned char, 32> bytes{};

    /** Wipes the bytes. */
    ~secp256k1_secret() { wipe(bytes.data(), bytes.size()); }
};

/**
 * The carver of a caller's workspace into the arrays of pointers libsecp256k1 takes, which
 * wipes the whole workspace when it is destroyed.
 *
 * Each array is aligned to `alignof(std::max_align_t)`, in the order the function's size
 * function lists them; an array of no elements takes no bytes and is `nullptr`.
 */
class secp256k1_workspace {
public:
    /**
     * Carves `lent_bytes`, from its first byte on.
     *
     * @param lent_bytes The caller's workspace.
     */
    explicit secp256k1_workspace(std::span<std::byte> lent_bytes) noexcept
        : lent_bytes_(lent_bytes) {}

    /** Not copyable: one carver wipes what it handed out. */
    secp256k1_workspace(secp256k1_workspace const&) = delete;
    /** Not copyable: one carver wipes what it handed out. */
    secp256k1_workspace& operator=(secp256k1_workspace const&) = delete;

    /**
     * Wipes the whole workspace: the arrays handed out, the padding before each, and the bytes
     * after the last, so that the workspace is zero when the function returns, wherever it
     * starts.
     */
    ~secp256k1_workspace() { wipe(lent_bytes_.data(), lent_bytes_.size()); }

    /**
     * The next array of `element_count` elements of `T`, aligned to `alignof(std::max_align_t)`.
     *
     * @tparam T The element, a type with no constructor to run (a pointer).
     * @param element_count The number of elements.
     * @return The array; `nullptr` for no elements, or when the rest of the workspace is short.
     */
    template <class T>
    [[nodiscard]] T* take(std::size_t element_count) noexcept {
        static_assert(
            std::is_trivially_default_constructible_v<T> && std::is_trivially_destructible_v<T>,
            "the workspace holds arrays of pointers");
        if (element_count == 0) {
            return nullptr;
        }
        std::size_t const array_size = element_count * sizeof(T);
        void* array_start = lent_bytes_.data() + used_size_;
        std::size_t free_size = lent_bytes_.size() - used_size_;
        if (std::align(alignof(std::max_align_t), array_size, array_start, free_size) == nullptr) {
            return nullptr;
        }
        used_size_ =
            static_cast<std::size_t>(static_cast<std::byte*>(array_start) - lent_bytes_.data()) +
            array_size;
        // Bytes the caller lent give their storage to an array of pointers, an implicit-lifetime
        // type ([intro.object]): the array exists once it is written.
        return static_cast<T*>(array_start);
    }

private:
    std::span<std::byte> lent_bytes_;
    std::size_t used_size_ = 0;
};

/**
 * Parses a public key of 33 bytes, compressed, or 65, uncompressed. libsecp256k1 also
 * accepts X9.62's hybrid forms, prefix 06 or 07, of 65 bytes; they are refused here, as every
 * prefix other than 02, 03 and 04 is.
 *
 * @param key_bytes The key, SEC1.
 * @param parsed_value Where the parsed key goes.
 * @return Whether it is a key: false in every way it can be wrong, `invalid_public_key` to the
 * caller.
 */
[[nodiscard]] inline bool secp256k1_parse_public_key(std::span<std::uint8_t const> key_bytes,
                                                     secp256k1_pubkey& parsed_value) noexcept {
    bool const is_sized =
        key_bytes.size() == 33 || (key_bytes.size() == 65 && key_bytes[0] == 0x04);
    return is_sized && secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed_value,
                                                 key_bytes.data(), key_bytes.size()) != 0;
}

/**
 * Whether 32 bytes of a compact signature, its r or its s, are not zero.
 *
 * @param half_bytes The 32 bytes.
 * @return Whether one byte is not zero.
 */
[[nodiscard]] inline bool secp256k1_nonzero(std::span<std::uint8_t const, 32> half_bytes) noexcept {
    return std::ranges::any_of(half_bytes,
                               [](std::uint8_t octet_value) { return octet_value != 0; });
}

/**
 * Parses a compact ECDSA signature, r then s, each below the group order and not zero.
 *
 * @param compact_signature The 64 bytes.
 * @param parsed_value Where the parsed signature goes.
 * @return Whether it is a signature: false in every way it can be wrong, `invalid_signature` to
 * the caller.
 */
[[nodiscard]] inline bool secp256k1_parse_compact(
    std::span<std::uint8_t const, 64> compact_signature,
    secp256k1_ecdsa_signature& parsed_value) noexcept {
    return secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed_value,
                                                   compact_signature.data()) != 0 &&
           secp256k1_nonzero(compact_signature.first<32>()) &&
           secp256k1_nonzero(compact_signature.last<32>());
}

/**
 * The compact form of a signature a DER parser read, refused when its r or its s is zero,
 * which is how libsecp256k1's parsers give a number not below the group order.
 *
 * @param parsed_value The signature.
 * @param output_bytes Where the 64 bytes go.
 * @return Whether r and s are both in range.
 */
[[nodiscard]] inline bool secp256k1_compact_of(
    secp256k1_ecdsa_signature const& parsed_value,
    std::array<std::uint8_t, 64>& output_bytes) noexcept {
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, output_bytes.data(),
                                                &parsed_value);
    return secp256k1_nonzero(std::span<std::uint8_t const, 64>(output_bytes).first<32>()) &&
           secp256k1_nonzero(std::span<std::uint8_t const, 64>(output_bytes).last<32>());
}

extern "C" {

/**
 * libsecp256k1's ECDH hash function that hashes nothing: the shared point's x coordinate,
 * 32 bytes, as Wycheproof's and NIP-44's ECDH give it. C linkage, as libsecp256k1's function
 * pointer type has.
 *
 * @return 1, always.
 */
inline int webcpp_crypto_detail_secp256k1_copy_x(unsigned char* output_bytes,
                                                 unsigned char const* x_coordinate,
                                                 unsigned char const* /*y_coordinate*/,
                                                 void* /*user_data*/) noexcept {
    std::memcpy(output_bytes, x_coordinate, 32);
    return 1;
}

/**
 * libsecp256k1's ECDH hash function that writes the shared point, SEC1 uncompressed:
 * 0x04, x, y, 65 bytes.
 *
 * @return 1, always.
 */
inline int webcpp_crypto_detail_secp256k1_copy_point(unsigned char* output_bytes,
                                                     unsigned char const* x_coordinate,
                                                     unsigned char const* y_coordinate,
                                                     void* /*user_data*/) noexcept {
    output_bytes[0] = 0x04;
    std::memcpy(output_bytes + 1, x_coordinate, 32);
    std::memcpy(output_bytes + 33, y_coordinate, 32);
    return 1;
}

}  // extern "C"

/**
 * Whether `Backend` is libsecp256k1, the one backend of `curves::secp256k1`.
 *
 * @tparam Backend The backend a function or the key pair names.
 */
template <class Backend>
inline constexpr bool secp256k1_backend = std::is_same_v<Backend, backends::secp256k1>;

/**
 * The refusal of `Backend` by a function of the secp256k1 family `Family`: empty for
 * libsecp256k1, the families' one backend; for any other, a specialisation per family whose body
 * is the family's generated refusal (`detail/capabilities.hpp`, design D33), which names the
 * backends that have the family. secp256k1 has no engine trait, so the refusal is reached here,
 * where `secp256k1_refuses_others` instantiates it. The generated macro cannot stand bare in a
 * function: for libsecp256k1 itself it asserts both "linked" and "not linked", so it always
 * fails there; in an engine's primary template, reached only for another backend, that is right.
 *
 * @tparam Family The family's tag, `families::secp256k1` or one of its modules'.
 * @tparam Backend The backend a function or the key pair names.
 * @tparam Accepted Whether `Backend` is libsecp256k1.
 */
template <class Family, class Backend, bool Accepted = secp256k1_backend<Backend>>
struct secp256k1_refusal {};

/**
 * The refusal of a backend other than libsecp256k1 by the family `families::secp256k1`: the key
 * pair and the functions of `curves/secp256k1.hpp`, `tweak.hpp` and `formats.hpp`.
 *
 * @tparam Backend The backend named.
 */
template <class Backend>
struct secp256k1_refusal<families::secp256k1, Backend, false> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECP256K1(Backend);
};

/**
 * True: reading it instantiates `secp256k1_refusal<Family, Backend>`, which stops the build with
 * the family's generated refusal where `Backend` is not libsecp256k1. A function's
 * `static_assert` of it is the family's one refusal, with no second message of its own.
 *
 * @tparam Family The family's tag.
 * @tparam Backend The backend a function or the key pair names.
 */
template <class Family, class Backend>
inline constexpr bool secp256k1_refuses_others = sizeof(secp256k1_refusal<Family, Backend>) != 0;

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/** The longest strict DER encoding of a secp256k1 ECDSA signature, in bytes. */
inline constexpr std::size_t max_der_size = 72;

/**
 * Memory a caller lends to a function over many keys, nonces or outputs, for libsecp256k1's
 * arrays of pointers, which crypto builds there and allocates nowhere.
 *
 * Each such function has a `*_workspace_size` that says how many bytes it needs, and wipes the
 * bytes before it returns; a short workspace is `invalid_input_size`, never an allocation.
 *
 * Tip: `alignas(std::max_align_t) std::array<std::byte, N>` on the stack, or a vector the
 * program owns.
 */
using workspace = std::span<std::byte>;

/** The two SEC1 encodings of a point. */
enum class point_form {
    /** 33 bytes: 02 or 03 by the parity of y, then x; Bitcoin's form. */
    compressed,
    /** 65 bytes: 04, x, y; Ethereum's form, and OpenSSL's default. */
    uncompressed,
};

/**
 * The size of a point in `Form`: 33 or 65.
 *
 * @tparam Form The SEC1 form.
 */
template <point_form Form>
inline constexpr std::size_t point_size =
    Form == point_form::compressed ? std::size_t{33} : std::size_t{65};

/** The size of a recoverable signature: r, s, then the recovery id. */
inline constexpr std::size_t recoverable_signature_size = 65;

/**
 * A secp256k1 public key, parsed: a point on the curve, never the identity
 * (libsecp256k1's `secp256k1_pubkey`).
 *
 * It holds nothing secret and is copied freely; it is made only by the functions that return
 * one, so that it is always valid.
 */
class public_key {
public:
    /**
     * Equal when the points are equal.
     *
     * @param left_key A key.
     * @param right_key Another key.
     * @return Whether they are the same point.
     */
    [[nodiscard]] friend bool operator==(public_key const& left_key,
                                         public_key const& right_key) noexcept {
        return compare(left_key, right_key) == 0;
    }

    /**
     * Ordered as their compressed encodings, BIP 327's KeySort (`secp256k1_ec_pubkey_cmp`).
     *
     * @param left_key A key.
     * @param right_key Another key.
     * @return The order of their compressed encodings, byte by byte.
     */
    [[nodiscard]] friend std::strong_ordering operator<=>(public_key const& left_key,
                                                          public_key const& right_key) noexcept {
        return compare(left_key, right_key) <=> 0;
    }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    public_key() noexcept = default;

    /**
     * libsecp256k1's comparison of two keys with the static context, which reads both as
     * compressed encodings. Both are valid points: no key is made otherwise, so the illegal
     * callback is never reached.
     *
     * @return Negative, zero or positive, as `memcmp`.
     */
    [[nodiscard]] static int compare(public_key const& left_key,
                                     public_key const& right_key) noexcept {
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        return secp256k1_ec_pubkey_cmp(secp256k1_context_static, &left_key.point_value_,
                                       &right_key.point_value_);
    }

    secp256k1_pubkey point_value_{};
};

/** A tweaked x-only key: the key and the parity of its point's y. */
struct tweaked_xonly_key {
    /** The 32-byte x-only key. */
    std::array<std::uint8_t, 32> key;
    /** 0 when the tweaked point's y is even, 1 when it is odd. */
    int parity;
};

/**
 * A secp256k1 key pair on libsecp256k1, with a signing context of its own in the resource it
 * is given, randomised from the random device as libsecp256k1 recommends.
 *
 * @tparam Backend `backends::secp256k1`, its only backend.
 */
template <class Backend = default_backend_t<families::secp256k1>>
class basic_keypair {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);

public:
    /** The backend. */
    using backend_type = Backend;
    /** The family of the capability table, `families::secp256k1`, which `supports_v` reads. */
    using family_type = families::secp256k1;
    /** The algorithm of the capability table: the family's own tag, its one algorithm. */
    using name_type = families::secp256k1;

    /**
     * Makes a key pair from a secret key.
     *
     * @param secret_bytes 32 bytes, not zero and below the group order.
     * @param memory_resource The resource of the signing context, the one allocation; it must
     * outlive the key pair.
     * @return The key pair; `invalid_key_size`; `invalid_secret_key`;
     * `entropy_unavailable`, also where there is no generator at all (an Emscripten audio
     * worklet), whatever the generator's own error; `backend_failure`, should libsecp256k1 refuse
     * the context's randomisation or the key pair after the secret's check, which v0.8.0 does not
     * (its `secp256k1_context_randomize` fails only on the static context, and
     * `secp256k1_keypair_create` only on a secret `secp256k1_ec_seckey_verify` refuses). A
     * failed allocation is the resource's to report; the seed is wiped then too.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> make(
        std::span<std::uint8_t const> secret_bytes,
        std::pmr::memory_resource* memory_resource = std::pmr::get_default_resource()) {
        if (secret_bytes.size() != 32) {
            return error::invalid_key_size;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        if (secp256k1_ec_seckey_verify(secp256k1_context_static, secret_bytes.data()) == 0) {
            return error::invalid_secret_key;
        }
        webcpp::crypto::detail::secp256k1_secret context_seed;
        auto const seed_result =
            random_device().fill(context_seed.bytes);  // lint-world: the context's seed
        if (!seed_result) {
            return webcpp::crypto::detail::secp256k1_seed_error(seed_result.error());
        }
        basic_keypair made_object;
        made_object.memory_ = memory_resource;
        made_object.context_ = secp256k1_context_preallocated_create(
            memory_resource->allocate(context_size(), alignof(std::max_align_t)),
            webcpp::crypto::detail::secp256k1_context_flags);
        int const randomise_status =
            secp256k1_context_randomize(made_object.context_, context_seed.bytes.data());
        if (randomise_status == 0 ||
            secp256k1_keypair_create(made_object.context_, &made_object.keypair_,
                                     secret_bytes.data()) == 0) {
            return error::backend_failure;
        }
        made_object.keyed_ = true;
        return made_object;
    }

    /**
     * Moves the key pair and its context; the source is wiped and empty.
     *
     * @param moved_source The source, empty afterwards.
     */
    basic_keypair(basic_keypair&& moved_source) noexcept
        : context_(std::exchange(moved_source.context_, nullptr)),
          memory_(moved_source.memory_),
          keypair_(moved_source.keypair_),
          keyed_(std::exchange(moved_source.keyed_, false)) {
        webcpp::crypto::detail::wipe_object(moved_source.keypair_);
    }

    /**
     * Moves over this key pair, which is wiped and gives its context back first.
     *
     * @param moved_source The source, empty afterwards.
     * @return This key pair.
     */
    basic_keypair& operator=(basic_keypair&& moved_source) noexcept {
        if (this != &moved_source) {
            release();
            context_ = std::exchange(moved_source.context_, nullptr);
            memory_ = moved_source.memory_;
            keypair_ = moved_source.keypair_;
            keyed_ = std::exchange(moved_source.keyed_, false);
            webcpp::crypto::detail::wipe_object(moved_source.keypair_);
        }
        return *this;
    }

    /** Not copyable: a key pair's secret and context have one owner. */
    basic_keypair(basic_keypair const&) = delete;
    /** Not copyable: a key pair's secret and context have one owner. */
    basic_keypair& operator=(basic_keypair const&) = delete;

    /** Wipes the key pair and gives the context back to its resource. */
    ~basic_keypair() { release(); }

    /**
     * The BIP340 x-only public key.
     *
     * @return 32 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 32>> xonly_public_key()
        const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_xonly_pubkey xonly_key{};
        std::array<std::uint8_t, 32> output_bytes{};
        secp256k1_keypair_xonly_pub(context_, &xonly_key, nullptr, &keypair_);
        secp256k1_xonly_pubkey_serialize(context_, output_bytes.data(), &xonly_key);
        return output_bytes;
    }

    /**
     * The public key, SEC1 compressed.
     *
     * @return 33 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 33>> public_key() const noexcept {
        return encoded_public_key<33>(webcpp::crypto::detail::secp256k1_compressed);
    }

    /**
     * The public key, SEC1 uncompressed.
     *
     * @return 65 bytes; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 65>> public_key_uncompressed()
        const noexcept {
        return encoded_public_key<65>(webcpp::crypto::detail::secp256k1_uncompressed);
    }

    /**
     * A BIP340 signature of a message of any length.
     *
     * @param message_bytes The message.
     * @param aux_random_bytes 32 bytes of fresh randomness, the caller's.
     * @return 64 bytes; `invalid_state` moved from; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign_schnorr(
        std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t const, 32> aux_random_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret aux_randomness;
        std::ranges::copy(aux_random_bytes, aux_randomness.bytes.begin());
        secp256k1_schnorrsig_extraparams extra_parameters = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        extra_parameters.ndata = aux_randomness.bytes.data();
        std::array<std::uint8_t, 64> output_bytes{};
        if (secp256k1_schnorrsig_sign_custom(context_, output_bytes.data(), message_bytes.data(),
                                             message_bytes.size(), &keypair_,
                                             &extra_parameters) == 0) {
            return error::backend_failure;
        }
        return output_bytes;
    }

    /**
     * An ECDSA signature of a 32-byte hash: RFC 6979's nonce, low-S, compact form.
     *
     * @param message_hash The hash.
     * @return 64 bytes, r then s; `invalid_state` moved from; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign_ecdsa(
        std::span<std::uint8_t const, 32> message_hash) const noexcept {
        return signed_ecdsa(message_hash, nullptr);
    }

    /**
     * A hedged ECDSA signature: RFC 6979's nonce with 32 bytes of the caller's fresh
     * randomness mixed in (libsecp256k1's `ndata`), so that a fault or a side channel on one
     * signing does not repeat on the next.
     *
     * @param message_hash The 32-byte hash signed.
     * @param extra_entropy 32 bytes from crypto's random device, new for each signature.
     * @return 64 bytes, r then s, low-S; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> sign_ecdsa(
        std::span<std::uint8_t const, 32> message_hash,
        std::span<std::uint8_t const, 32> extra_entropy) const noexcept {
        webcpp::crypto::detail::secp256k1_secret nonce_data;
        std::ranges::copy(extra_entropy, nonce_data.bytes.begin());
        return signed_ecdsa(message_hash, nonce_data.bytes.data());
    }

    /**
     * An ECDSA signature of a 32-byte hash with its recovery id: RFC 6979's nonce, low-S, as
     * `sign_ecdsa` (the same r and s), then the id from which `recover` finds the key.
     *
     * @param message_hash The 32-byte hash signed.
     * @return 65 bytes, r, s and the id 0 to 3; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, recoverable_signature_size>>
    sign_recoverable(std::span<std::uint8_t const, 32> message_hash) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret_bytes;
        secp256k1_keypair_sec(context_, secret_bytes.bytes.data(), &keypair_);
        secp256k1_ecdsa_recoverable_signature signature_value{};
        if (secp256k1_ecdsa_sign_recoverable(context_, &signature_value, message_hash.data(),
                                             secret_bytes.bytes.data(), nullptr, nullptr) == 0) {
            return error::backend_failure;
        }
        std::array<std::uint8_t, recoverable_signature_size> output_bytes{};
        int recovery_id = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(context_, output_bytes.data(),
                                                                &recovery_id, &signature_value);
        output_bytes[64] = static_cast<std::uint8_t>(recovery_id);
        return output_bytes;
    }

    /**
     * The SHA-256 of the compressed shared point with a peer's public key, libsecp256k1's
     * default.
     *
     * @param public_key_bytes The peer's key, SEC1: 33 bytes, prefix 02 or 03, or 65, prefix 04.
     * @return 32 secret bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<secret<32>> ecdh(
        std::span<std::uint8_t const> public_key_bytes) const noexcept {
        return agree<32>(public_key_bytes, nullptr);
    }

    /**
     * The shared point's x coordinate, unhashed: what Wycheproof's ECDH vectors, Nostr's NIP-44
     * and other protocols that hash it themselves take.
     *
     * Tip: the x coordinate is not a key; a protocol derives its keys from it (NIP-44 with
     * HKDF), and that derivation is the protocol's.
     *
     * @param public_key_bytes The peer's key, SEC1, as `ecdh` takes it.
     * @return 32 secret bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<secret<32>> ecdh_x(
        std::span<std::uint8_t const> public_key_bytes) const noexcept {
        return agree<32>(public_key_bytes,
                         webcpp::crypto::detail::webcpp_crypto_detail_secp256k1_copy_x);
    }

    /**
     * The shared point itself, SEC1 uncompressed (0x04, x, y).
     *
     * @param public_key_bytes The peer's key, SEC1, as `ecdh` takes it.
     * @return 65 secret bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<secret<65>> ecdh_point(
        std::span<std::uint8_t const> public_key_bytes) const noexcept {
        return agree<65>(public_key_bytes,
                         webcpp::crypto::detail::webcpp_crypto_detail_secp256k1_copy_point);
    }

    /**
     * Tweaks this key pair in place by a 32-byte tweak t: its x-only public key P becomes
     * P + t*G, and its secret key follows (`secp256k1_keypair_xonly_tweak_add`).
     *
     * The caller computes the tweak, as a protocol defines it.
     *
     * Allocates nothing; the pair keeps its context, its wiping and its behaviour when moved
     * from.
     *
     * @param tweak_bytes The 32-byte tweak, a big-endian scalar.
     * @return Nothing; `invalid_state` moved from; `invalid_secret_key` for a tweak not below
     * the group order, or one that gives no valid key (negligible, but checked), after which
     * the pair is wiped and empty, as moved from.
     */
    [[nodiscard]] boost::system::result<void> tweak_xonly(
        std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        if (secp256k1_keypair_xonly_tweak_add(context_, &keypair_, tweak_bytes.data()) == 0) {
            release();
            return error::invalid_secret_key;
        }
        return {};
    }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    basic_keypair() noexcept = default;

    /**
     * The public key in the SEC1 form `flags` names.
     *
     * @tparam N The form's size, 33 or 65.
     * @param flags libsecp256k1's flag of the form.
     * @return `N` bytes; `invalid_state` moved from.
     */
    template <std::size_t N>
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, N>> encoded_public_key(
        unsigned flags) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_pubkey public_point{};
        std::array<std::uint8_t, N> output_bytes{};
        std::size_t written_size = output_bytes.size();
        secp256k1_keypair_pub(context_, &public_point, &keypair_);
        secp256k1_ec_pubkey_serialize(context_, output_bytes.data(), &written_size, &public_point,
                                      flags);
        return output_bytes;
    }

    /**
     * An ECDSA signature with RFC 6979's nonce, `nonce_data` mixed in when it is not null.
     *
     * @param message_hash The 32-byte hash signed.
     * @param nonce_data 32 bytes of extra entropy, libsecp256k1's `ndata`, or null.
     * @return 64 bytes, r then s, low-S; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> signed_ecdsa(
        std::span<std::uint8_t const, 32> message_hash,
        unsigned char const* nonce_data) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret_bytes;
        secp256k1_keypair_sec(context_, secret_bytes.bytes.data(), &keypair_);
        secp256k1_ecdsa_signature signature_bytes{};
        std::array<std::uint8_t, 64> output_bytes{};
        if (secp256k1_ecdsa_sign(context_, &signature_bytes, message_hash.data(),
                                 secret_bytes.bytes.data(), nullptr, nonce_data) == 0) {
            return error::backend_failure;
        }
        secp256k1_ecdsa_signature_serialize_compact(context_, output_bytes.data(),
                                                    &signature_bytes);
        return output_bytes;
    }

    /**
     * ECDH with a peer's public key, its output written by `hash_function` into the secret:
     * libsecp256k1's SHA-256 when it is null.
     *
     * @tparam N The output's size, which `hash_function` writes.
     * @param public_key_bytes The peer's key, SEC1, as `ecdh` takes it.
     * @param hash_function libsecp256k1's hash function, or null for its default.
     * @return `N` secret bytes; `invalid_state`; `invalid_public_key`; `backend_failure`.
     */
    template <std::size_t N>
    [[nodiscard]] boost::system::result<secret<N>> agree(
        std::span<std::uint8_t const> public_key_bytes,
        secp256k1_ecdh_hash_function hash_function) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        secp256k1_pubkey parsed_value{};
        if (!webcpp::crypto::detail::secp256k1_parse_public_key(public_key_bytes, parsed_value)) {
            return error::invalid_public_key;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret_bytes;
        secp256k1_keypair_sec(context_, secret_bytes.bytes.data(), &keypair_);
        secret<N> shared_secret;
        if (secp256k1_ecdh(context_, shared_secret.writable().data(), &parsed_value,
                           secret_bytes.bytes.data(), hash_function, nullptr) == 0) {
            return error::backend_failure;
        }
        return shared_secret;
    }

    static std::size_t context_size() noexcept {
        return secp256k1_context_preallocated_size(webcpp::crypto::detail::secp256k1_context_flags);
    }

    void release() noexcept {
        webcpp::crypto::detail::wipe_object(keypair_);
        keyed_ = false;
        if (context_ != nullptr) {
            secp256k1_context_preallocated_destroy(context_);
            memory_->deallocate(context_, context_size(), alignof(std::max_align_t));
            context_ = nullptr;
        }
    }

    secp256k1_context* context_ = nullptr;
    std::pmr::memory_resource* memory_ = nullptr;
    secp256k1_keypair keypair_{};
    bool keyed_ = false;
};

/** A key pair on libsecp256k1. */
using keypair = basic_keypair<>;

}  // namespace webcpp::crypto::curves::secp256k1

namespace webcpp::crypto::detail {

template <class Backend>
inline bool secp256k1_access::keyed(
    curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept {
    return key_pair.keyed_;
}

template <class Backend>
inline secp256k1_context const* secp256k1_access::context(
    curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept {
    return key_pair.context_;
}

template <class Backend>
inline secp256k1_keypair const& secp256k1_access::pair(
    curves::secp256k1::basic_keypair<Backend> const& key_pair) noexcept {
    return key_pair.keypair_;
}

inline secp256k1_pubkey const& secp256k1_access::point(
    curves::secp256k1::public_key const& key) noexcept {
    return key.point_value_;
}

inline secp256k1_pubkey& secp256k1_access::point(curves::secp256k1::public_key& key) noexcept {
    return key.point_value_;
}

inline curves::secp256k1::public_key secp256k1_access::make_public_key() noexcept {
    return {};
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/**
 * Parses a public key: 33 bytes with prefix 02 or 03, or 65 with prefix 04 (X9.62's hybrid
 * prefixes 06 and 07 are refused, as everywhere in crypto).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param encoded_key The key, SEC1.
 * @return The key; `invalid_public_key` for any other length or prefix, or a point off the curve.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> parse_public_key(
    std::span<std::uint8_t const> encoded_key) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    public_key parsed_key = access::make_public_key();
    if (!webcpp::crypto::detail::secp256k1_parse_public_key(encoded_key,
                                                            access::point(parsed_key))) {
        return error::invalid_public_key;
    }
    return parsed_key;
}

/**
 * Serialises a public key in `Form`.
 *
 * @tparam Form The SEC1 form, `compressed` by default.
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_key The key.
 * @return 33 bytes (`compressed`, the default) or 65 (`uncompressed`).
 */
template <point_form Form = point_form::compressed,
          class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] std::array<std::uint8_t, point_size<Form>> serialize_public_key(
    public_key const& parsed_key) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::array<std::uint8_t, point_size<Form>> output_bytes{};
    std::size_t written_size = output_bytes.size();
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, output_bytes.data(), &written_size,
                                  &webcpp::crypto::detail::secp256k1_access::point(parsed_key),
                                  Form == point_form::compressed
                                      ? webcpp::crypto::detail::secp256k1_compressed
                                      : webcpp::crypto::detail::secp256k1_uncompressed);
    return output_bytes;
}

/**
 * The public key that made a recoverable signature of a 32-byte hash
 * (`secp256k1_ecdsa_recover`), as Ethereum identifies a transaction's signer.
 *
 * Tip: recovery finds some key for almost any signature; the signature is the expected
 * signer's only when the key recovered is the one expected.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param recoverable_signature 65 bytes: r, s, then the recovery id, 0 to 3.
 * @param message_hash The 32-byte hash signed.
 * @return The key; `invalid_signature` for a recovery id above 3, an r or an s not below the
 * group order, or a signature from which no key is recovered.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<public_key> recover(
    std::span<std::uint8_t const, recoverable_signature_size> recoverable_signature,
    std::span<std::uint8_t const, 32> message_hash) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // libsecp256k1 checks the id with ARG_CHECK, whose callback aborts: refused first here.
    int const recovery_id = recoverable_signature[64];
    if (recovery_id > 3) {
        return error::invalid_signature;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    secp256k1_ecdsa_recoverable_signature parsed_value{};
    public_key recovered_key = access::make_public_key();
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_context_static, &parsed_value,
                                                            recoverable_signature.data(),
                                                            recovery_id) == 0 ||
        secp256k1_ecdsa_recover(secp256k1_context_static, &access::point(recovered_key),
                                &parsed_value, message_hash.data()) == 0) {
        return error::invalid_signature;
    }
    return recovered_key;
}

/**
 * Verifies a BIP340 signature with libsecp256k1's static context, which allocates nothing,
 * after its self-test (`include/secp256k1.h:235-247`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_bytes 64 bytes.
 * @param message_bytes The message, of any length.
 * @param xonly_key_bytes 32 bytes.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<void> verify_schnorr(
    std::span<std::uint8_t const, 64> signature_bytes, std::span<std::uint8_t const> message_bytes,
    std::span<std::uint8_t const, 32> xonly_key_bytes) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_xonly_pubkey parsed_key{};
    if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed_key,
                                     xonly_key_bytes.data()) == 0) {
        return error::invalid_public_key;
    }
    if (secp256k1_schnorrsig_verify(secp256k1_context_static, signature_bytes.data(),
                                    message_bytes.data(), message_bytes.size(), &parsed_key) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * Verifies an ECDSA signature in compact form with the static context, after its self-test;
 * a high-S signature is refused, as libsecp256k1 refuses it.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_bytes 64 bytes, r then s.
 * @param message_hash The 32-byte hash signed.
 * @param public_key_bytes SEC1: 33 bytes, prefix 02 or 03, or 65, prefix 04.
 * @return Nothing; `invalid_public_key`; `invalid_signature`.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<void> verify_ecdsa(
    std::span<std::uint8_t const, 64> signature_bytes,
    std::span<std::uint8_t const, 32> message_hash,
    std::span<std::uint8_t const> public_key_bytes) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_pubkey parsed_key{};
    if (!webcpp::crypto::detail::secp256k1_parse_public_key(public_key_bytes, parsed_key)) {
        return error::invalid_public_key;
    }
    secp256k1_ecdsa_signature parsed_value{};
    if (secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed_value,
                                                signature_bytes.data()) == 0 ||
        secp256k1_ecdsa_verify(secp256k1_context_static, &parsed_value, message_hash.data(),
                               &parsed_key) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * Encodes a compact ECDSA signature as strict DER (BIP66), with libsecp256k1's own encoder.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param compact_signature 64 bytes, r then s.
 * @param output_bytes At least `max_der_size` bytes, whatever this signature's length; nothing is
 * written on an error.
 * @return The number of bytes written, at most `max_der_size`; `invalid_input_size` when
 * `output_bytes` is shorter than `max_der_size`; `invalid_signature` when r or s is zero or not
 * below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::size_t> to_der(
    std::span<std::uint8_t const, 64> compact_signature,
    std::span<std::uint8_t> output_bytes) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    if (output_bytes.size() < max_der_size) {
        return error::invalid_input_size;
    }
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(compact_signature, parsed_value)) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, max_der_size> der_signature{};
    std::size_t der_size = der_signature.size();
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, der_signature.data(),
                                            &der_size, &parsed_value);
    std::ranges::copy(std::span<std::uint8_t const>(der_signature).first(der_size),
                      output_bytes.begin());
    return der_size;
}

/**
 * Decodes a strict DER ECDSA signature (BIP66, `secp256k1_ecdsa_signature_parse_der`) to its
 * compact form.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param der_signature The encoding, exactly: nothing may follow it.
 * @return 64 bytes, r then s; `invalid_signature` for anything that is not strict DER, and for
 * an r or an s that is zero or not below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> from_der(
    std::span<std::uint8_t const> der_signature) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    if (der_signature.empty()) {
        return error::invalid_signature;
    }
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    std::array<std::uint8_t, 64> output_bytes{};
    if (secp256k1_ecdsa_signature_parse_der(secp256k1_context_static, &parsed_value,
                                            der_signature.data(), der_signature.size()) == 0 ||
        !webcpp::crypto::detail::secp256k1_compact_of(parsed_value, output_bytes)) {
        return error::invalid_signature;
    }
    return output_bytes;
}

/**
 * The low-S form of a compact ECDSA signature (`secp256k1_ecdsa_signature_normalize`), the
 * only form `verify_ecdsa` accepts; a low-S signature is returned unchanged.
 *
 * Tip: normalizing makes a signature malleable on purpose; only for signatures from a signer
 * that does not enforce low-S.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param compact_signature 64 bytes, r then s.
 * @return 64 bytes, r then n - s when s was above half the group order;
 * `invalid_signature` when r or s is zero or not below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::array<std::uint8_t, 64>> normalize_ecdsa(
    std::span<std::uint8_t const, 64> compact_signature) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(compact_signature, parsed_value)) {
        return error::invalid_signature;
    }
    secp256k1_ecdsa_signature_normalize(secp256k1_context_static, &parsed_value, &parsed_value);
    std::array<std::uint8_t, 64> output_bytes{};
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, output_bytes.data(),
                                                &parsed_value);
    return output_bytes;
}

/**
 * Tweaks an x-only public key by a 32-byte tweak t: P + t*G, with libsecp256k1's static
 * context, which allocates nothing (`secp256k1_xonly_pubkey_tweak_add`).
 *
 * The caller computes the tweak, as a protocol defines it.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param xonly_key_bytes The 32-byte x-only key P.
 * @param tweak_bytes The 32-byte tweak, a big-endian scalar.
 * @return The tweaked x-only key and its parity; `invalid_public_key` for a key that is not a
 * point's x; `invalid_secret_key` for a tweak not below the group order, or one that gives
 * no valid key (negligible, but checked).
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<tweaked_xonly_key> tweak_xonly(
    std::span<std::uint8_t const, 32> xonly_key_bytes,
    std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_xonly_pubkey parsed_key{};
    if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed_key,
                                     xonly_key_bytes.data()) == 0) {
        return error::invalid_public_key;
    }
    secp256k1_pubkey tweaked_point{};
    if (secp256k1_xonly_pubkey_tweak_add(secp256k1_context_static, &tweaked_point, &parsed_key,
                                         tweak_bytes.data()) == 0) {
        return error::invalid_secret_key;
    }
    secp256k1_xonly_pubkey tweaked_xonly{};
    tweaked_xonly_key tweaked_result{};
    secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &tweaked_xonly,
                                       &tweaked_result.parity, &tweaked_point);
    secp256k1_xonly_pubkey_serialize(secp256k1_context_static, tweaked_result.key.data(),
                                     &tweaked_xonly);
    return tweaked_result;
}

}  // namespace webcpp::crypto::curves::secp256k1

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
