// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1 on libsecp256k1: a key pair made from its 32-byte secret key, which `secret()` gives
 back, and its typed public key, `curves::secp256k1::public_key`, made from SEC1 bytes by
 `public_key::from_bytes` and giving its compressed, uncompressed and x-only forms;
 `key.sign(scheme, input)` with `crypto::ecdsa_sha256` (hedged too),
 `crypto::ecdsa_sha256_recoverable`, `crypto::ecdsa_keccak256_recoverable` (Ethereum's, over
 Keccak-256: a message needs `/third_party//xkcp`) and `crypto::schnorr` (BIP340), the input a
 message or, for ECDSA, `crypto::prehashed{digest}`, each giving its own signature type,
 `ecdsa_signature`, `recoverable_signature` (both recoverable schemes) and `schnorr_signature`;
 `crypto::verify` of ECDSA against the public key and of Schnorr against the public key or its
 32-byte x-only form; `recover`, the signer's key, under either recoverable scheme; ECDH
 in three forms, `agree` (the shared x, as P-256's), `agree_hashed` and `agree_point`, each a
 secret; ECDSA's DER form, `normalize_low_s` and `is_low_s`, the tweak of an x-only key, and the
 workspace a function over many keys borrows.

 @see "secp256k1", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the context's randomisation and generate()'s key
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#ifdef WEBCPP_HASH_HAS_XKCP
#include <webcpp/hash/keccak.hpp>  // crypto::ecdsa_keccak256_recoverable's hash of a message

#include <boost/hash2/digest.hpp>
#endif

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

/** The tag of `curves::secp256k1::ecdsa_signature`. */
struct secp256k1_ecdsa_signature_tag {
    /** No recovery id. */
    static constexpr bool recoverable = false;
};

/** The tag of `curves::secp256k1::recoverable_signature`. */
struct secp256k1_recoverable_signature_tag {
    /** The last byte is the recovery id. */
    static constexpr bool recoverable = true;
};

/** The tag of `curves::secp256k1::schnorr_signature`. */
struct secp256k1_schnorr_signature_tag {
    /** No recovery id. */
    static constexpr bool recoverable = false;
};

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
     * @param typed_key The public key.
     * @return Its `secp256k1_pubkey`.
     */
    [[nodiscard]] static secp256k1_pubkey const& point(
        curves::secp256k1::public_key const& typed_key) noexcept;

    /**
     * A public key's point, to be written by the function that makes the key.
     *
     * @param typed_key The public key.
     * @return Its `secp256k1_pubkey`.
     */
    [[nodiscard]] static secp256k1_pubkey& point(curves::secp256k1::public_key& typed_key) noexcept;

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
     * @param opaque_object The object.
     * @return Its member, `const` when the object is.
     */
    template <class Opaque>
    [[nodiscard]] static auto& native(Opaque& opaque_object) noexcept {
        return opaque_object.native_value_;
    }
};

// NOLINTBEGIN(bugprone-signed-bitwise): libsecp256k1's macros shift a signed constant
#if defined(WEBCPP_CRYPTO_DETAIL_CT_VALGRIND) || defined(WEBCPP_CRYPTO_DETAIL_CT_MSAN)
/**
 * The flags of a context that signs and verifies, under a constant-time checker:
 * `SECP256K1_CONTEXT_DECLASSIFY`, so that libsecp256k1 marks its own public values public (a
 * nonce's retry, a verdict), as its `ctime_tests.c` does; the checker then reports any other
 * branch on a secret.
 */
inline constexpr unsigned secp256k1_context_flags = SECP256K1_CONTEXT_DECLASSIFY;
#else
/** The flags of a context that signs and verifies: none. */
inline constexpr unsigned secp256k1_context_flags = SECP256K1_CONTEXT_NONE;
#endif

/** The flag of the SEC1 compressed form. */
inline constexpr unsigned secp256k1_compressed = SECP256K1_EC_COMPRESSED;

/** The flag of the SEC1 uncompressed form. */
inline constexpr unsigned secp256k1_uncompressed = SECP256K1_EC_UNCOMPRESSED;
// NOLINTEND(bugprone-signed-bitwise)

/**
 * Whether libsecp256k1 accepted: what it returned on a secret, marked public for the
 * constant-time checks (`WEBCPP_CRYPTO_DETAIL_DECLASSIFY`) where webcpp branches on it, as its
 * `ctime_tests.c` marks each verdict.
 *
 * @param returned_code What the function returned: 1, or 0 when it refused.
 * @return Whether it accepted.
 */
[[nodiscard]] inline bool secp256k1_accepted(int returned_code) noexcept {
    // Not const: the comparison reads it again after the mark (detail/declassify.hpp's tip).
    // NOLINTNEXTLINE(misc-const-correctness): see above
    int accepted_verdict = returned_code;
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&accepted_verdict, sizeof accepted_verdict);
    return accepted_verdict != 0;
}

/**
 * A key pair's public key, marked public (`WEBCPP_CRYPTO_DETAIL_DECLASSIFY`): libsecp256k1
 * derives it from the secret and marks it public only where it loads the key pair itself, and
 * its `ctime_tests.c` marks a key pair's public key by hand where it reads one.
 *
 * @param secp_context The key pair's context, or the static one.
 * @param key_pair libsecp256k1's key pair.
 * @return The public key.
 */
[[nodiscard]] inline secp256k1_pubkey secp256k1_public_point(
    secp256k1_context const* secp_context, secp256k1_keypair const& key_pair) noexcept {
    secp256k1_pubkey public_point{};
    // libsecp256k1 returns 1 always: a key pair holds its public key.
    static_cast<void>(secp256k1_keypair_pub(secp_context, &public_point, &key_pair));
    WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&public_point, sizeof public_point);
    return public_point;
}

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
 * A public key's BIP340 x-only form, with libsecp256k1's static context; the parity of y is
 * dropped. The caller has read the canary and run the self-test.
 *
 * @param point_value A valid point, as every `public_key` holds.
 * @return The x-only key.
 */
[[nodiscard]] inline secp256k1_xonly_pubkey secp256k1_xonly_of(
    secp256k1_pubkey const& point_value) noexcept {
    secp256k1_xonly_pubkey xonly_key{};
    // libsecp256k1 returns 1 always: every valid point has an x-only form.
    static_cast<void>(secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &xonly_key,
                                                         nullptr, &point_value));
    return xonly_key;
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

/**
 * The 32-byte digest ECDSA over SHA-256 signs and verifies: a marker's digest, copied, or the
 * SHA-256 of a message.
 *
 * @tparam Input A message or `prehashed<32>`, which `check_input` has accepted.
 * @param signing_input The message or the marker.
 * @return The digest.
 */
template <class Input>
[[nodiscard]] std::array<std::uint8_t, 32> secp256k1_digest(Input const& signing_input) noexcept {
    if constexpr (is_prehashed_v<Input>) {
        std::array<std::uint8_t, 32> digest_bytes{};
        std::ranges::copy(signing_input.digest, digest_bytes.begin());
        return digest_bytes;
    } else {
        return sha256_of(message_bytes(signing_input));
    }
}

/**
 * The 32-byte digest Ethereum's recoverable ECDSA signs and recovers from: a marker's digest,
 * copied, or the Keccak-256 of a message (webcpp::hash's `keccak_256`, the original padding,
 * never SHA3-256), which needs XKCP: without `/third_party//xkcp`, a message stops the build.
 *
 * @tparam Input A message or `prehashed<32>`, which `check_input` has accepted.
 * @param signing_input The message or the marker.
 * @return The digest.
 */
template <class Input>
[[nodiscard]] std::array<std::uint8_t, 32> secp256k1_keccak_digest(
    Input const& signing_input) noexcept {
    std::array<std::uint8_t, 32> digest_bytes{};
    if constexpr (is_prehashed_v<Input>) {
        std::ranges::copy(signing_input.digest, digest_bytes.begin());
    } else {
#ifdef WEBCPP_HASH_HAS_XKCP
        auto const bytes_of_message = message_bytes(signing_input);
        ::webcpp::hash::keccak_256 keccak_hasher;
        keccak_hasher.update(bytes_of_message.data(), bytes_of_message.size());
        static_assert(
            std::is_same_v<::webcpp::hash::keccak_256::result_type, boost::hash2::digest<32>>);
        auto const hash_result = keccak_hasher.result();
        std::copy_n(hash_result.data(), digest_bytes.size(), digest_bytes.begin());
#else
        static_assert(refused_v<Input>,
                      "webcpp::crypto: crypto::ecdsa_keccak256_recoverable hashes a message with "
                      "webcpp::hash's keccak_256, which needs XKCP: add /third_party//xkcp to the "
                      "program's Jamfile, or sign crypto::prehashed{digest}.");
#endif
    }
    return digest_bytes;
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

/**
 * Verifies a BIP340 signature against an x-only key already parsed, with libsecp256k1's static
 * context: the end of every verification of `schnorr`, whose public functions hold the guard.
 *
 * @param signature_bytes 64 bytes.
 * @param message_bytes The signed message, as given.
 * @param xonly_key The signer's x-only key.
 * @return Nothing; `invalid_signature`.
 */
[[nodiscard]] inline boost::system::result<void> secp256k1_verify_schnorr(
    std::span<std::uint8_t const, 64> signature_bytes, std::span<std::uint8_t const> message_bytes,
    secp256k1_xonly_pubkey const& xonly_key) noexcept {
    if (secp256k1_schnorrsig_verify(secp256k1_context_static, signature_bytes.data(),
                                    message_bytes.data(), message_bytes.size(), &xonly_key) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * Verifies a BIP340 signature against a public key's point, through its x-only form, with
 * libsecp256k1's static context: the work of `public_key::verify` and of `crypto::verify` of
 * `schnorr` against the typed key, which hold the guard.
 *
 * @tparam Backend The backend, libsecp256k1.
 * @tparam Input A message; anything else stops the build.
 * @param signature_bytes The signature's 64 bytes.
 * @param message_input The signed message, as given.
 * @param point_value The signer's point.
 * @return Nothing; `invalid_signature` for a signature that does not verify.
 */
template <class Backend, class Input>
[[nodiscard]] boost::system::result<void> secp256k1_verify_schnorr_key(
    std::span<std::uint8_t const, 64> signature_bytes, Input const& message_input,
    secp256k1_pubkey const& point_value) noexcept {
    check_input<schnorr_t, Input, Backend>();
    if constexpr (input_valid_v<schnorr_t, Input, Backend>) {
        auto const bytes_of_message = message_bytes(message_input);
        read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        auto const xonly_key = secp256k1_xonly_of(point_value);
        return secp256k1_verify_schnorr(signature_bytes, bytes_of_message, xonly_key);
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

/**
 * Verifies an ECDSA signature over SHA-256 against a public key's point, with libsecp256k1's
 * static context, after its self-test: the work of `public_key::verify` and of `crypto::verify`
 * of `ecdsa_sha256`, which hold the guard.
 *
 * @tparam Backend The backend, libsecp256k1.
 * @tparam Input A message or `crypto::prehashed<32>`; anything else stops the build.
 * @param signature_bytes The signature's 64 bytes, r then s.
 * @param signing_input The signed message, hashed with SHA-256 here, or the marker of its digest.
 * @param point_value The signer's point.
 * @return Nothing; `invalid_signature` for an r or an s not below the group order, a high S, or a
 * signature that does not verify.
 */
template <class Backend, class Input>
[[nodiscard]] boost::system::result<void> secp256k1_verify_ecdsa(
    std::span<std::uint8_t const, 64> signature_bytes, Input const& signing_input,
    secp256k1_pubkey const& point_value) noexcept {
    check_input<ecdsa_sha256_t, Input, Backend>();
    if constexpr (input_valid_v<ecdsa_sha256_t, Input, Backend>) {
        auto const digest_bytes = secp256k1_digest(signing_input);
        read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        secp256k1_ecdsa_signature parsed_value{};
        if (secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static, &parsed_value,
                                                    signature_bytes.data()) == 0 ||
            secp256k1_ecdsa_verify(secp256k1_context_static, &parsed_value, digest_bytes.data(),
                                   &point_value) == 0) {
            return error::invalid_signature;
        }
        return {};
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/**
 * A secp256k1 ECDSA signature, 64 bytes, r then s: what `sign(crypto::ecdsa_sha256, ...)` gives
 * and `crypto::verify(crypto::ecdsa_sha256, ...)` takes.
 *
 * Each of r and s is 32 bytes big-endian (libsecp256k1's compact form). `from_bytes` checks the
 * size alone; whether r and s are in range, and s low, is verification's and `normalize_low_s`'s
 * judgment.
 */
using ecdsa_signature = detail::basic_signature<detail::secp256k1_ecdsa_signature_tag, 64>;

/**
 * A secp256k1 recoverable ECDSA signature, 65 bytes, r, s and the recovery id: what `sign` gives
 * with `crypto::ecdsa_sha256_recoverable` and with `crypto::ecdsa_keccak256_recoverable`, and
 * what `recover` takes, under the scheme that signed it (design R20).
 *
 * `recovery_id()` reads its last byte. `from_bytes` checks the size alone; `recover` refuses an id
 * above 3.
 */
using recoverable_signature =
    detail::basic_signature<detail::secp256k1_recoverable_signature_tag, 65>;

/**
 * A BIP340 Schnorr signature, 64 bytes, R's x then s: what `sign(crypto::schnorr, ...)` gives and
 * `crypto::verify(crypto::schnorr, ...)` takes.
 *
 * `from_bytes` checks the size alone.
 */
using schnorr_signature = detail::basic_signature<detail::secp256k1_schnorr_signature_tag, 64>;

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
 * The size of a point in `Form`: 33 for the compressed form, 65 for the uncompressed one.
 *
 * @tparam Form The SEC1 form.
 */
template <point_form Form>
inline constexpr std::size_t point_size = 33;

/** The size of an uncompressed point: 65. */
template <>
inline constexpr std::size_t point_size<point_form::uncompressed> = 65;

/** The size of a recoverable signature: r, s, then the recovery id. */
inline constexpr std::size_t recoverable_signature_size = 65;

/**
 * A secp256k1 public key: a point on the curve, never the identity (libsecp256k1's
 * `secp256k1_pubkey`), which `crypto::verify` takes, of ECDSA and of Schnorr, and a key pair's
 * `agree` takes as its peer.
 *
 * It holds nothing secret and is copied freely; it is made only by `from_bytes` and by the
 * functions that return one (a key pair's `public_key()`, `recover`, the tweaks), so that it is
 * always valid. It gives its bytes in each of its forms: `compressed()` (33, Bitcoin's),
 * `uncompressed()` (65, Ethereum's) and `xonly()` (32, BIP340's).
 */
class public_key {
public:
    /**
     * Makes a public key from SEC1 bytes, 33 with prefix 02 or 03, or 65 with prefix 04.
     *
     * X9.62's hybrid prefixes 06 and 07 are refused, as everywhere in crypto. The point is
     * checked: it is on the curve.
     *
     * @tparam Backend The backend, `backends::secp256k1`.
     * @param encoded_key The key, SEC1.
     * @return The key; `invalid_public_key` for any other length or prefix, or a point off the
     * curve.
     */
    template <class Backend = default_backend_t<families::secp256k1>>
    [[nodiscard]] static boost::system::result<public_key> from_bytes(
        std::span<std::uint8_t const> encoded_key) noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        public_key made_key;
        if (!webcpp::crypto::detail::secp256k1_parse_public_key(encoded_key,
                                                                made_key.point_value_)) {
            return error::invalid_public_key;
        }
        return made_key;
    }

    /**
     * The key, SEC1 compressed: 02 or 03 by the parity of y, then x; Bitcoin's form.
     *
     * @return 33 bytes.
     */
    [[nodiscard]] std::array<std::uint8_t, point_size<point_form::compressed>> compressed()
        const noexcept {
        detail::timing_guard const timing_scope;
        return encoded<point_size<point_form::compressed>>(
            webcpp::crypto::detail::secp256k1_compressed);
    }

    /**
     * The key, SEC1 uncompressed: 04, x, y; Ethereum's form, and OpenSSL's default.
     *
     * @return 65 bytes.
     */
    [[nodiscard]] std::array<std::uint8_t, point_size<point_form::uncompressed>> uncompressed()
        const noexcept {
        detail::timing_guard const timing_scope;
        return encoded<point_size<point_form::uncompressed>>(
            webcpp::crypto::detail::secp256k1_uncompressed);
    }

    /**
     * The key's BIP340 x-only form, its x coordinate, which `crypto::verify(crypto::schnorr, ...)`
     * takes as the key itself does; the parity of y is dropped.
     *
     * @return 32 bytes.
     */
    [[nodiscard]] std::array<std::uint8_t, 32> xonly() const noexcept {
        detail::timing_guard const timing_scope;
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        auto const xonly_key = webcpp::crypto::detail::secp256k1_xonly_of(point_value_);
        std::array<std::uint8_t, 32> output_bytes{};
        secp256k1_xonly_pubkey_serialize(secp256k1_context_static, output_bytes.data(), &xonly_key);
        return output_bytes;
    }

    /**
     * Verifies a signature with this key, of ECDSA over SHA-256 or of BIP340's Schnorr (design
     * R22): `crypto::verify(signing_scheme, signature_value, signing_input, key)`, of which it is
     * the member form, with the same work, results and refusals.
     *
     * ECDSA's high S is refused, as libsecp256k1 refuses it; Schnorr reads the key's x-only form.
     *
     * @tparam Backend The backend, `backends::secp256k1`, the only one; another stops the build.
     * @tparam Scheme `crypto::ecdsa_sha256_t` or `crypto::schnorr_t`; another scheme stops the
     * build.
     * @tparam Signature The scheme's signature type, `curves::secp256k1::ecdsa_signature` or
     * `curves::secp256k1::schnorr_signature`; another type, bytes included, stops the build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included; or, for ECDSA, `crypto::prehashed<32>`; anything else stops the build.
     * @param signing_scheme `crypto::ecdsa_sha256` or `crypto::schnorr`.
     * @param signature_value The signature: r then s for ECDSA, BIP340's signature for Schnorr;
     * bytes from a peer are made into one by its type's `from_bytes`.
     * @param signing_input For ECDSA, the message, hashed with SHA-256 inside the call, or
     * `crypto::prehashed{digest}`; for Schnorr, the message itself.
     * @return Nothing; `invalid_signature` for an r or an s not below the group order, a high S,
     * or a signature that does not verify.
     */
    template <class Backend = default_backend_t<families::secp256k1>, class Scheme, class Signature,
              class Input>
    [[nodiscard]] boost::system::result<void> verify([[maybe_unused]] Scheme signing_scheme,
                                                     Signature const& signature_value,
                                                     Input const& signing_input) const noexcept {
        detail::timing_guard const timing_scope;
        static_assert(
            webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
        constexpr bool is_ecdsa = std::is_same_v<Scheme, ecdsa_sha256_t>;
        constexpr bool is_schnorr = std::is_same_v<Scheme, schnorr_t>;
        static_assert(is_ecdsa || is_schnorr,
                      "webcpp::crypto: a secp256k1 public key verifies crypto::ecdsa_sha256 or "
                      "crypto::schnorr; a crypto::ecdsa_sha256_recoverable or a "
                      "crypto::ecdsa_keccak256_recoverable signature gives its key to "
                      "curves::secp256k1::recover.");
        if constexpr (is_ecdsa) {
            return webcpp::crypto::detail::secp256k1_verify_ecdsa<Backend>(
                webcpp::crypto::detail::checked_signature_bytes<ecdsa_signature, ecdsa_sha256_t>(
                    signature_value),
                signing_input, point_value_);
        } else if constexpr (is_schnorr) {
            return webcpp::crypto::detail::secp256k1_verify_schnorr_key<Backend>(
                webcpp::crypto::detail::checked_signature_bytes<schnorr_signature, schnorr_t>(
                    signature_value),
                signing_input, point_value_);
        } else {
            // Never compiled into a program: an assertion above stopped the build.
            return error::invalid_signature;
        }
    }

    /**
     * Equal when the points are equal.
     *
     * @param left_key A key.
     * @param right_key Another key.
     * @return Whether they are the same point.
     */
    [[nodiscard]] friend bool operator==(public_key const& left_key,
                                         public_key const& right_key) noexcept {
        detail::timing_guard const timing_scope;
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
        detail::timing_guard const timing_scope;
        return compare(left_key, right_key) <=> 0;
    }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    public_key() noexcept = default;

    /**
     * The key in the SEC1 form `encoding_flags` names, with libsecp256k1's static context.
     *
     * @tparam N The form's size, 33 or 65.
     * @param encoding_flags libsecp256k1's flag of the form.
     * @return `N` bytes.
     */
    template <std::size_t N>
    [[nodiscard]] std::array<std::uint8_t, N> encoded(unsigned encoding_flags) const noexcept {
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        std::array<std::uint8_t, N> output_bytes{};
        std::size_t written_size = output_bytes.size();
        secp256k1_ec_pubkey_serialize(secp256k1_context_static, output_bytes.data(), &written_size,
                                      &point_value_, encoding_flags);
        return output_bytes;
    }

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
    /** The public key's type, which `crypto::verify` and `agree` take. */
    using public_key_type = ::webcpp::crypto::curves::secp256k1::public_key;
    /** The size of the secret key, which `from_secret` takes and `secret()` gives. */
    static constexpr std::size_t secret_key_size = 32;
    /** The most draws `generate` makes: 32 bytes that are not a secret key are drawn again. */
    static constexpr int max_draws = 4;

    /**
     * Makes a key pair from a secret key, as a program that kept `secret()` loads it again.
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
    [[nodiscard]] static boost::system::result<basic_keypair> from_secret(
        std::span<std::uint8_t const> secret_bytes,
        std::pmr::memory_resource* memory_resource = std::pmr::get_default_resource()) {
        detail::timing_guard const timing_scope;
        if (secret_bytes.size() != secret_key_size) {
            return error::invalid_key_size;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        if (!webcpp::crypto::detail::secp256k1_accepted(
                secp256k1_ec_seckey_verify(secp256k1_context_static, secret_bytes.data()))) {
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
        bool const context_randomised = webcpp::crypto::detail::secp256k1_accepted(
            secp256k1_context_randomize(made_object.context_, context_seed.bytes.data()));
        if (!context_randomised ||
            !webcpp::crypto::detail::secp256k1_accepted(secp256k1_keypair_create(
                made_object.context_, &made_object.keypair_, secret_bytes.data()))) {
            return error::backend_failure;
        }
        made_object.keyed_ = true;
        return made_object;
    }

    /**
     * Generates a key pair from the system's source: draws a 32-byte secret key from the system's
     * generator and makes the key pair from it, drawing again when the 32 bytes are not a
     * secret key (zero or not below the group order, which happens with a probability near
     * 2^-128), at most `max_draws` (four) draws in all.
     *
     * @param memory_resource The resource of the signing context, the one allocation; it must
     * outlive the key pair.
     * @return The key pair; `entropy_unavailable` when the system's generator fails, there is
     * none, or four draws were not a secret key; `backend_failure` as `from_secret` returns it.
     */
    [[nodiscard]] static boost::system::result<basic_keypair> generate(
        std::pmr::memory_resource* memory_resource = std::pmr::get_default_resource()) {
        detail::timing_guard const timing_scope;
        for (int draw_count = 0; draw_count < max_draws; ++draw_count) {
            crypto::secret<secret_key_size> secret_key;
            auto const entropy_drawn =
                random_device().fill(secret_key.writable());  // lint-world: the secret key
            if (!entropy_drawn) {
                // The generator's not_supported (an Emscripten audio worklet) is the same
                // failure for a key pair: one error to handle.
                return error::entropy_unavailable;
            }
            auto made_pair = from_secret(secret_key.bytes(), memory_resource);
            if (made_pair || made_pair.error() != error::invalid_secret_key) {
                return made_pair;
            }
        }
        return error::entropy_unavailable;
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
     * The public key, which `crypto::verify` takes, and `agree` as a peer's; its `compressed()`,
     * `uncompressed()` and `xonly()` give its bytes.
     *
     * @return The public key; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<public_key_type> public_key() const noexcept {
        detail::timing_guard const timing_scope;
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        using access = webcpp::crypto::detail::secp256k1_access;
        public_key_type made_key = access::make_public_key();
        access::point(made_key) =
            webcpp::crypto::detail::secp256k1_public_point(context_, keypair_);
        return made_key;
    }

    /**
     * The secret key (`secp256k1_keypair_sec`), for a program that keeps the key pair and makes it
     * again with `from_secret`, or exports it.
     *
     * @return 32 secret bytes, big-endian; `invalid_state` moved from.
     */
    [[nodiscard]] boost::system::result<crypto::secret<secret_key_size>> secret() const noexcept {
        detail::timing_guard const timing_scope;
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        crypto::secret<secret_key_size> secret_key;
        // libsecp256k1 returns 1 always: a key pair holds its secret key.
        static_cast<void>(secp256k1_keypair_sec(context_, secret_key.writable().data(), &keypair_));
        return secret_key;
    }

    /**
     * Signs with one of secp256k1's four schemes: ECDSA over SHA-256 with RFC 6979's nonce, low
     * S, as libsecp256k1 signs; the same with the recovery id; Ethereum's recoverable ECDSA, the
     * same over Keccak-256 (EIP-2's low S); or BIP340's Schnorr, with 32 bytes of auxiliary
     * randomness drawn from the system's generator, as BIP340 recommends.
     *
     * @tparam Scheme `crypto::ecdsa_sha256_t`, `crypto::ecdsa_sha256_recoverable_t`,
     * `crypto::ecdsa_keccak256_recoverable_t` or `crypto::schnorr_t`; another scheme stops the
     * build.
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
     * empty included; or, for the three ECDSA schemes, `crypto::prehashed<32>`; anything else
     * stops the build, and so does a message for `ecdsa_keccak256_recoverable` in a program that
     * does not link `/third_party//xkcp`.
     * @param signing_scheme `crypto::ecdsa_sha256`, `crypto::ecdsa_sha256_recoverable`,
     * `crypto::ecdsa_keccak256_recoverable` or `crypto::schnorr`.
     * @param signing_input For ECDSA, the message, hashed inside the call with SHA-256, or with
     * Keccak-256 for `ecdsa_keccak256_recoverable`, or `crypto::prehashed{digest}`, a 32-byte
     * digest signed as given (a Bitcoin sighash, an EIP-191 or EIP-712 digest, a transaction's
     * hash); for Schnorr, the message itself, signed as given.
     * @return The scheme's signature: an `ecdsa_signature`, r then s, for `ecdsa_sha256`; a
     * `recoverable_signature`, r, s and the recovery id 0 to 3, for `ecdsa_sha256_recoverable` and
     * `ecdsa_keccak256_recoverable`; a `schnorr_signature`, BIP340's, for `schnorr`;
     * `invalid_state` moved from;
     * `entropy_unavailable` when Schnorr's auxiliary randomness cannot be drawn;
     * `backend_failure`.
     */
    template <class Scheme, class Input>
    [[nodiscard]] boost::system::result<
        webcpp::crypto::detail::signature_of_t<basic_keypair, Scheme>>
    sign([[maybe_unused]] Scheme signing_scheme, Input const& signing_input) const noexcept {
        detail::timing_guard const timing_scope;
        constexpr bool has_scheme = std::is_same_v<Scheme, ecdsa_sha256_t> ||
                                    std::is_same_v<Scheme, ecdsa_sha256_recoverable_t> ||
                                    std::is_same_v<Scheme, ecdsa_keccak256_recoverable_t> ||
                                    std::is_same_v<Scheme, schnorr_t>;
        static_assert(has_scheme,
                      "webcpp::crypto: a secp256k1 key signs with crypto::ecdsa_sha256, "
                      "crypto::ecdsa_sha256_recoverable, crypto::ecdsa_keccak256_recoverable or "
                      "crypto::schnorr.");
        if constexpr (has_scheme) {
            detail::check_input<Scheme, Input, Backend>();
            if constexpr (!detail::input_valid_v<Scheme, Input, Backend>) {
                // Never compiled into a program: check_input stopped the build.
                return error::backend_failure;
            } else if constexpr (std::is_same_v<Scheme, schnorr_t>) {
                return signed_schnorr_drawn(detail::message_bytes(signing_input));
            } else if constexpr (std::is_same_v<Scheme, ecdsa_sha256_t>) {
                return signed_ecdsa(webcpp::crypto::detail::secp256k1_digest(signing_input),
                                    nullptr);
            } else if constexpr (std::is_same_v<Scheme, ecdsa_sha256_recoverable_t>) {
                return signed_recoverable(webcpp::crypto::detail::secp256k1_digest(signing_input));
            } else {
                return signed_recoverable(
                    webcpp::crypto::detail::secp256k1_keccak_digest(signing_input));
            }
        } else {
            // Never compiled into a program: the assertion above stopped the build.
            return error::backend_failure;
        }
    }

    /**
     * A hedged ECDSA signature over SHA-256: RFC 6979's nonce with 32 bytes of the caller's fresh
     * randomness mixed in (libsecp256k1's `ndata`), so that a fault or a side channel on one
     * signing does not repeat on the next; low S.
     *
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, or
     * `crypto::prehashed<32>`; anything else stops the build.
     * @param signing_scheme `crypto::ecdsa_sha256`.
     * @param signing_input The message, hashed with SHA-256 inside the call, or
     * `crypto::prehashed{digest}`, a 32-byte digest signed as given.
     * @param extra_entropy 32 bytes from crypto's random device, new for each signature.
     * @return The signature, r then s; `invalid_state` moved from; `backend_failure`.
     */
    template <class Input>
    [[nodiscard]] boost::system::result<ecdsa_signature> sign(
        [[maybe_unused]] ecdsa_sha256_t signing_scheme, Input const& signing_input,
        std::span<std::uint8_t const, 32> extra_entropy) const noexcept {
        detail::timing_guard const timing_scope;
        detail::check_input<ecdsa_sha256_t, Input, Backend>();
        if constexpr (detail::input_valid_v<ecdsa_sha256_t, Input, Backend>) {
            webcpp::crypto::detail::secp256k1_secret nonce_data;
            std::ranges::copy(extra_entropy, nonce_data.bytes.begin());
            return signed_ecdsa(webcpp::crypto::detail::secp256k1_digest(signing_input),
                                nonce_data.bytes.data());
        } else {
            // Never compiled into a program: check_input stopped the build.
            return error::backend_failure;
        }
    }

    /**
     * A BIP340 signature with the caller's 32 bytes of auxiliary randomness: for BIP340's test
     * vectors, and for a program that draws its own.
     *
     * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`; a
     * `crypto::prehashed` marker, or anything else, stops the build.
     * @param signing_scheme `crypto::schnorr`.
     * @param message_input The message, of any length, signed as given.
     * @param auxiliary_random_bytes 32 bytes of fresh randomness, the caller's.
     * @return The signature; `invalid_state` moved from; `backend_failure`.
     */
    template <class Input>
    [[nodiscard]] boost::system::result<schnorr_signature> sign(
        [[maybe_unused]] schnorr_t signing_scheme, Input const& message_input,
        std::span<std::uint8_t const, 32> auxiliary_random_bytes) const noexcept {
        detail::timing_guard const timing_scope;
        detail::check_input<schnorr_t, Input, Backend>();
        if constexpr (detail::input_valid_v<schnorr_t, Input, Backend>) {
            return signed_schnorr(detail::message_bytes(message_input), auxiliary_random_bytes);
        } else {
            // Never compiled into a program: check_input stopped the build.
            return error::backend_failure;
        }
    }

    /**
     * ECDH with a peer's public key: the shared point's x coordinate, unhashed, as P-256's `agree`
     * and WebCrypto's `deriveBits` give it, and what Wycheproof's ECDH vectors, Nostr's NIP-44
     * and other protocols that hash it themselves take.
     *
     * Tip: the x coordinate is not a key; a protocol derives its keys from it (NIP-44 with
     * HKDF), and that derivation is the protocol's.
     *
     * @param peer_key The peer's public key.
     * @return 32 secret bytes; `invalid_state` moved from; `backend_failure`, which a valid key
     * pair and a valid public key cannot cause.
     */
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree(
        public_key_type const& peer_key) const noexcept {
        detail::timing_guard const timing_scope;
        return ecdh_secret<32>(peer_key,
                               webcpp::crypto::detail::webcpp_crypto_detail_secp256k1_copy_x);
    }

    /**
     * ECDH with a peer's public key, hashed as libsecp256k1 hashes it by default: the SHA-256 of
     * the compressed shared point.
     *
     * @param peer_key The peer's public key.
     * @return 32 secret bytes; `invalid_state` moved from; `backend_failure`, which a valid key
     * pair and a valid public key cannot cause.
     */
    [[nodiscard]] boost::system::result<crypto::secret<32>> agree_hashed(
        public_key_type const& peer_key) const noexcept {
        detail::timing_guard const timing_scope;
        return ecdh_secret<32>(peer_key, nullptr);
    }

    /**
     * ECDH with a peer's public key: the shared point itself, SEC1 uncompressed (0x04, x, y).
     *
     * @param peer_key The peer's public key.
     * @return 65 secret bytes; `invalid_state` moved from; `backend_failure`, which a valid key
     * pair and a valid public key cannot cause.
     */
    [[nodiscard]] boost::system::result<crypto::secret<65>> agree_point(
        public_key_type const& peer_key) const noexcept {
        detail::timing_guard const timing_scope;
        return ecdh_secret<65>(peer_key,
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
        detail::timing_guard const timing_scope;
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        if (!webcpp::crypto::detail::secp256k1_accepted(
                secp256k1_keypair_xonly_tweak_add(context_, &keypair_, tweak_bytes.data()))) {
            release();
            return error::invalid_secret_key;
        }
        return {};
    }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    basic_keypair() noexcept = default;

    /**
     * An ECDSA signature with RFC 6979's nonce, `nonce_data` mixed in when it is not null.
     *
     * @param message_hash The 32-byte hash signed.
     * @param nonce_data 32 bytes of extra entropy, libsecp256k1's `ndata`, or null.
     * @return The signature, r then s, low-S; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<ecdsa_signature> signed_ecdsa(
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
        if (!webcpp::crypto::detail::secp256k1_accepted(
                secp256k1_ecdsa_sign(context_, &signature_bytes, message_hash.data(),
                                     secret_bytes.bytes.data(), nullptr, nonce_data))) {
            return error::backend_failure;
        }
        secp256k1_ecdsa_signature_serialize_compact(context_, output_bytes.data(),
                                                    &signature_bytes);
        return webcpp::crypto::detail::signature_access::of<ecdsa_signature>(output_bytes);
    }

    /**
     * An ECDSA signature with its recovery id, RFC 6979's nonce, low S: the r and s of
     * `signed_ecdsa` with no extra entropy.
     *
     * @param message_hash The 32-byte hash signed.
     * @return The signature, r, s and the id 0 to 3; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<recoverable_signature> signed_recoverable(
        std::span<std::uint8_t const, 32> message_hash) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret_bytes;
        secp256k1_keypair_sec(context_, secret_bytes.bytes.data(), &keypair_);
        secp256k1_ecdsa_recoverable_signature signature_value{};
        if (!webcpp::crypto::detail::secp256k1_accepted(
                secp256k1_ecdsa_sign_recoverable(context_, &signature_value, message_hash.data(),
                                                 secret_bytes.bytes.data(), nullptr, nullptr))) {
            return error::backend_failure;
        }
        std::array<std::uint8_t, recoverable_signature_size> output_bytes{};
        int recovery_id = 0;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(context_, output_bytes.data(),
                                                                &recovery_id, &signature_value);
        output_bytes[64] = static_cast<std::uint8_t>(recovery_id);
        return webcpp::crypto::detail::signature_access::of<recoverable_signature>(output_bytes);
    }

    /**
     * A BIP340 signature with the caller's auxiliary randomness, copied into a buffer wiped when
     * the call ends, the one copy crypto makes of it.
     *
     * @param message_bytes The message, of any length.
     * @param auxiliary_random_bytes 32 bytes of auxiliary randomness.
     * @return The signature; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<schnorr_signature> signed_schnorr(
        std::span<std::uint8_t const> message_bytes,
        std::span<std::uint8_t const, 32> auxiliary_random_bytes) const noexcept {
        webcpp::crypto::detail::secp256k1_secret auxiliary_randomness;
        std::ranges::copy(auxiliary_random_bytes, auxiliary_randomness.bytes.begin());
        return signed_schnorr(message_bytes, auxiliary_randomness);
    }

    /**
     * A BIP340 signature with auxiliary randomness already in a buffer the caller owns and wipes,
     * read in place: no second copy is made.
     *
     * @param message_bytes The message, of any length.
     * @param auxiliary_randomness The 32 bytes of auxiliary randomness.
     * @return The signature; `invalid_state`; `backend_failure`.
     */
    [[nodiscard]] boost::system::result<schnorr_signature> signed_schnorr(
        std::span<std::uint8_t const> message_bytes,
        webcpp::crypto::detail::secp256k1_secret& auxiliary_randomness) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_schnorrsig_extraparams extra_parameters = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        extra_parameters.ndata = auxiliary_randomness.bytes.data();
        std::array<std::uint8_t, 64> output_bytes{};
        if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_schnorrsig_sign_custom(
                context_, output_bytes.data(), message_bytes.data(), message_bytes.size(),
                &keypair_, &extra_parameters))) {
            return error::backend_failure;
        }
        return webcpp::crypto::detail::signature_access::of<schnorr_signature>(output_bytes);
    }

    /**
     * A BIP340 signature with 32 bytes of auxiliary randomness drawn from the system's generator
     * into a buffer wiped when the call ends, their one home: the signing reads them there.
     *
     * @param message_bytes The message, of any length.
     * @return The signature; `invalid_state` moved from, before any draw; `entropy_unavailable`
     * when the generator fails, or there is none (an Emscripten audio worklet); `backend_failure`.
     */
    [[nodiscard]] boost::system::result<schnorr_signature> signed_schnorr_drawn(
        std::span<std::uint8_t const> message_bytes) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::secp256k1_secret auxiliary_randomness;
        auto const entropy_drawn =
            random_device().fill(auxiliary_randomness.bytes);  // lint-world: BIP340's aux_rand
        if (!entropy_drawn) {
            return error::entropy_unavailable;
        }
        return signed_schnorr(message_bytes, auxiliary_randomness);
    }

    /**
     * ECDH with a peer's public key, its output written by `hash_function` into the secret:
     * libsecp256k1's SHA-256 when it is null. The worker of `agree`, `agree_hashed` and
     * `agree_point`, which hold the guard.
     *
     * @tparam N The output's size, which `hash_function` writes.
     * @param peer_key The peer's public key.
     * @param hash_function libsecp256k1's hash function, or null for its default.
     * @return `N` secret bytes; `invalid_state`; `backend_failure`.
     */
    template <std::size_t N>
    [[nodiscard]] boost::system::result<crypto::secret<N>> ecdh_secret(
        public_key_type const& peer_key,
        secp256k1_ecdh_hash_function hash_function) const noexcept {
        if (!keyed_) {
            return error::invalid_state;
        }
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        webcpp::crypto::detail::secp256k1_secret secret_bytes;
        secp256k1_keypair_sec(context_, secret_bytes.bytes.data(), &keypair_);
        crypto::secret<N> shared_secret;
        if (!webcpp::crypto::detail::secp256k1_accepted(
                secp256k1_ecdh(context_, shared_secret.writable().data(),
                               &webcpp::crypto::detail::secp256k1_access::point(peer_key),
                               secret_bytes.bytes.data(), hash_function, nullptr))) {
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
    curves::secp256k1::public_key const& typed_key) noexcept {
    return typed_key.point_value_;
}

inline secp256k1_pubkey& secp256k1_access::point(
    curves::secp256k1::public_key& typed_key) noexcept {
    return typed_key.point_value_;
}

inline curves::secp256k1::public_key secp256k1_access::make_public_key() noexcept {
    return {};
}

/**
 * The public key that made a recoverable signature of a 32-byte digest
 * (`secp256k1_ecdsa_recover`), the work of `recover` under both recoverable schemes, unguarded:
 * each `recover` holds the guard.
 *
 * A high S is accepted, as libsecp256k1's recovery and Ethereum's `ecrecover` accept it.
 *
 * @param signature_bytes The signature: r, s, then the recovery id.
 * @param message_hash The 32-byte digest signed.
 * @return The key; `invalid_signature` for a recovery id above 3, an r or an s not below the
 * group order, or a signature from which no key is recovered.
 */
[[nodiscard]] inline boost::system::result<curves::secp256k1::public_key> secp256k1_recovered(
    std::array<std::uint8_t, curves::secp256k1::recoverable_signature_size> const& signature_bytes,
    std::span<std::uint8_t const, 32> message_hash) noexcept {
    read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // libsecp256k1 checks the id with ARG_CHECK, whose callback aborts: refused first here.
    int const recovery_id = signature_bytes[curves::secp256k1::recoverable_signature_size - 1];
    if (recovery_id > 3) {
        return error::invalid_signature;
    }
    secp256k1_selftest();
    secp256k1_ecdsa_recoverable_signature parsed_value{};
    curves::secp256k1::public_key recovered_key = secp256k1_access::make_public_key();
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_static, &parsed_value, signature_bytes.data(), recovery_id) == 0 ||
        secp256k1_ecdsa_recover(secp256k1_context_static, &secp256k1_access::point(recovered_key),
                                &parsed_value, message_hash.data()) == 0) {
        return error::invalid_signature;
    }
    return recovered_key;
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1 {

/**
 * The public key that made a recoverable signature (`secp256k1_ecdsa_recover`) of ECDSA over
 * SHA-256: the same inputs as `sign(crypto::ecdsa_sha256_recoverable, signing_input)`.
 *
 * Tip: recovery finds some key for almost any signature; the signature is the expected
 * signer's only when the key recovered is the one expected.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @tparam Signature `curves::secp256k1::recoverable_signature`; another type, bytes included,
 * stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, or
 * `crypto::prehashed<32>`; anything else stops the build.
 * @param signing_scheme `crypto::ecdsa_sha256_recoverable`.
 * @param signature_value The signature: r, s, then the recovery id, 0 to 3; 65 bytes from a peer
 * are made into one by `recoverable_signature::from_bytes`.
 * @param signing_input The signed message, hashed with SHA-256 inside the call, or
 * `crypto::prehashed{digest}`, the 32-byte digest signed.
 * @return The key; `invalid_signature` for a recovery id above 3, an r or an s not below the
 * group order, or a signature from which no key is recovered.
 */
template <class Backend = default_backend_t<families::secp256k1>, class Signature, class Input>
[[nodiscard]] boost::system::result<public_key> recover(
    [[maybe_unused]] ecdsa_sha256_recoverable_t signing_scheme, Signature const& signature_value,
    Input const& signing_input) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    auto const& signature_bytes =
        detail::checked_signature_bytes<recoverable_signature, ecdsa_sha256_recoverable_t>(
            signature_value);
    detail::check_input<ecdsa_sha256_recoverable_t, Input, Backend>();
    if constexpr (detail::input_valid_v<ecdsa_sha256_recoverable_t, Input, Backend>) {
        return webcpp::crypto::detail::secp256k1_recovered(
            signature_bytes, webcpp::crypto::detail::secp256k1_digest(signing_input));
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

/**
 * The public key that made a signature of Ethereum's recoverable ECDSA over Keccak-256
 * (`secp256k1_ecdsa_recover`), as Ethereum identifies a transaction's or a message's signer: the
 * same inputs as `sign(crypto::ecdsa_keccak256_recoverable, signing_input)`.
 *
 * Ethereum's `v` is the program's to turn into the recovery id (27 + id for `personal_sign`,
 * 35 + 2 x chain id + id for EIP-155, the id itself, `yParity`, for a typed transaction), and the
 * address the program's to compute from the key: crypto computes neither.
 *
 * A high S is accepted, as libsecp256k1's recovery and Ethereum's `ecrecover` accept it; EIP-2
 * refuses one in a transaction, which a program checks with `is_low_s` where it applies.
 *
 * Tip: recovery finds some key for almost any signature; the signature is the expected
 * signer's only when the key, or its address, is the one expected.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @tparam Signature `curves::secp256k1::recoverable_signature`; another type, bytes included,
 * stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, or
 * `crypto::prehashed<32>`; anything else stops the build, and so does a message in a program
 * that does not link `/third_party//xkcp`.
 * @param signing_scheme `crypto::ecdsa_keccak256_recoverable`.
 * @param signature_value The signature: r, s, then the recovery id, 0 to 3; 65 bytes from a peer
 * are made into one by `recoverable_signature::from_bytes`.
 * @param signing_input The signed message, hashed with Keccak-256 inside the call, or
 * `crypto::prehashed{digest}`, the 32-byte digest signed (an EIP-191 or EIP-712 digest, a
 * transaction's hash).
 * @return The key; `invalid_signature` for a recovery id above 3, an r or an s not below the
 * group order, or a signature from which no key is recovered.
 */
template <class Backend = default_backend_t<families::secp256k1>, class Signature, class Input>
[[nodiscard]] boost::system::result<public_key> recover(
    [[maybe_unused]] ecdsa_keccak256_recoverable_t signing_scheme, Signature const& signature_value,
    Input const& signing_input) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    auto const& signature_bytes =
        detail::checked_signature_bytes<recoverable_signature, ecdsa_keccak256_recoverable_t>(
            signature_value);
    detail::check_input<ecdsa_keccak256_recoverable_t, Input, Backend>();
    if constexpr (detail::input_valid_v<ecdsa_keccak256_recoverable_t, Input, Backend>) {
        return webcpp::crypto::detail::secp256k1_recovered(
            signature_bytes, webcpp::crypto::detail::secp256k1_keccak_digest(signing_input));
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

/**
 * Encodes a compact ECDSA signature as strict DER (BIP66), with libsecp256k1's own encoder.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_value The signature.
 * @param der_output At least `max_der_size` bytes, whatever this signature's length; nothing is
 * written on an error.
 * @return The number of bytes written, at most `max_der_size`; `invalid_input_size` when
 * `der_output` is shorter than `max_der_size`; `invalid_signature` when r or s is zero or not
 * below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<std::size_t> to_der(
    ecdsa_signature const& signature_value, std::span<std::uint8_t> der_output) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    if (der_output.size() < max_der_size) {
        return error::invalid_input_size;
    }
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(signature_value.bytes(), parsed_value)) {
        return error::invalid_signature;
    }
    std::array<std::uint8_t, max_der_size> der_signature{};
    std::size_t der_size = der_signature.size();
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, der_signature.data(),
                                            &der_size, &parsed_value);
    std::ranges::copy(std::span<std::uint8_t const>(der_signature).first(der_size),
                      der_output.begin());
    return der_size;
}

/**
 * Decodes a strict DER ECDSA signature (BIP66, `secp256k1_ecdsa_signature_parse_der`) to its
 * compact form.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param der_signature The encoding, exactly: nothing may follow it.
 * @return The signature, r then s; `invalid_signature` for anything that is not strict DER, and
 * for an r or an s that is zero or not below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<ecdsa_signature> from_der(
    std::span<std::uint8_t const> der_signature) noexcept {
    detail::timing_guard const timing_scope;
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
    return webcpp::crypto::detail::signature_access::of<ecdsa_signature>(output_bytes);
}

/**
 * The low-S form of a compact ECDSA signature (`secp256k1_ecdsa_signature_normalize`), the
 * only form `crypto::verify` accepts on secp256k1; a low-S signature is returned unchanged.
 *
 * Tip: `sign` gives the low form already; normalizing makes a signature malleable on purpose,
 * only for signatures from a signer that does not enforce low S.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_value The signature.
 * @return The signature, r then n - s when s was above half the group order;
 * `invalid_signature` when r or s is zero or not below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] boost::system::result<ecdsa_signature> normalize_low_s(
    ecdsa_signature const& signature_value) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(signature_value.bytes(), parsed_value)) {
        return error::invalid_signature;
    }
    secp256k1_ecdsa_signature_normalize(secp256k1_context_static, &parsed_value, &parsed_value);
    std::array<std::uint8_t, 64> output_bytes{};
    secp256k1_ecdsa_signature_serialize_compact(secp256k1_context_static, output_bytes.data(),
                                                &parsed_value);
    return webcpp::crypto::detail::signature_access::of<ecdsa_signature>(output_bytes);
}

/**
 * Whether a compact ECDSA signature is in its low-S form, the only form `crypto::verify` accepts
 * on secp256k1, as a protocol checks what it relays (Bitcoin's standardness); `sign` gives the
 * low form.
 *
 * It does not verify the signature.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_value The signature.
 * @return True exactly when 0 < r < n and 0 < s <= (n - 1) / 2, n the group order.
 */
template <class Backend = default_backend_t<families::secp256k1>>
[[nodiscard]] bool is_low_s(ecdsa_signature const& signature_value) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    secp256k1_ecdsa_signature parsed_value{};
    if (!webcpp::crypto::detail::secp256k1_parse_compact(signature_value.bytes(), parsed_value)) {
        return false;
    }
    // libsecp256k1 returns 1 when s was high, and writes nothing when the output is null.
    return secp256k1_ecdsa_signature_normalize(secp256k1_context_static, nullptr, &parsed_value) ==
           0;
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
    detail::timing_guard const timing_scope;
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

namespace webcpp::crypto {

/**
 * Verifies an ECDSA signature over SHA-256 with a secp256k1 public key, with libsecp256k1's
 * static context, which allocates nothing, after its self-test.
 *
 * A high S is refused, as libsecp256k1 refuses it (Bitcoin's policy); `sign` gives low S, and
 * `curves::secp256k1::normalize_low_s` makes a high one low.
 *
 * @tparam Backend The backend, `backends::secp256k1`, the only one; another stops the build.
 * @tparam Signature `curves::secp256k1::ecdsa_signature`; another type, a signature of another
 * curve or scheme or bytes, stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or `crypto::prehashed<32>`; anything else stops the build.
 * @param signing_scheme `crypto::ecdsa_sha256`.
 * @param signature_value The signature, r then s; bytes from a peer are made into one by
 * `curves::secp256k1::ecdsa_signature::from_bytes`, and DER by `curves::secp256k1::from_der`.
 * @param signing_input The signed message, hashed with SHA-256 inside the call; or
 * `crypto::prehashed{digest}`, the 32-byte digest signed (a Bitcoin sighash).
 * @param public_key The signer's public key: a key pair's `public_key()`, or
 * `curves::secp256k1::public_key::from_bytes` of its SEC1 bytes.
 * @return Nothing; `invalid_signature` for an r or an s not below the group order, a high S, or a
 * signature that does not verify.
 */
template <class Backend = default_backend_t<families::secp256k1>, class Signature, class Input>
[[nodiscard]] boost::system::result<void> verify(
    [[maybe_unused]] ecdsa_sha256_t signing_scheme, Signature const& signature_value,
    Input const& signing_input, curves::secp256k1::public_key const& public_key) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    return detail::secp256k1_verify_ecdsa<Backend>(
        detail::checked_signature_bytes<curves::secp256k1::ecdsa_signature, ecdsa_sha256_t>(
            signature_value),
        signing_input, detail::secp256k1_access::point(public_key));
}

/**
 * Verifies a BIP340 signature with libsecp256k1's static context, which allocates nothing, after
 * its self-test (`include/secp256k1.h:235-247`).
 *
 * @tparam Backend The backend, `backends::secp256k1`, the only one; another stops the build.
 * @tparam Signature `curves::secp256k1::schnorr_signature`; another type, bytes included, stops
 * the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included; a `crypto::prehashed` marker, or anything else, stops the build.
 * @param signing_scheme `crypto::schnorr`.
 * @param signature_value The signature; 64 bytes from a peer are made into one by
 * `curves::secp256k1::schnorr_signature::from_bytes`.
 * @param message_input The signed message, as given.
 * @param xonly_public_key The signer's 32-byte x-only key (a public key's `xonly()`, a taproot
 * output key, MuSig2's aggregate key).
 * @return Nothing; `invalid_public_key` for 32 bytes that are no point's x; `invalid_signature`
 * for a signature that does not verify.
 */
template <class Backend = default_backend_t<families::secp256k1>, class Signature, class Input>
[[nodiscard]] boost::system::result<void> verify(
    [[maybe_unused]] schnorr_t signing_scheme, Signature const& signature_value,
    Input const& message_input, std::span<std::uint8_t const, 32> xonly_public_key) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    auto const& signature_bytes =
        detail::checked_signature_bytes<curves::secp256k1::schnorr_signature, schnorr_t>(
            signature_value);
    detail::check_input<schnorr_t, Input, Backend>();
    if constexpr (detail::input_valid_v<schnorr_t, Input, Backend>) {
        auto const message_bytes = detail::message_bytes(message_input);
        detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        secp256k1_xonly_pubkey parsed_key{};
        if (secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed_key,
                                         xonly_public_key.data()) == 0) {
            return error::invalid_public_key;
        }
        return detail::secp256k1_verify_schnorr(signature_bytes, message_bytes, parsed_key);
    } else {
        // Never compiled into a program: check_input stopped the build.
        return error::invalid_signature;
    }
}

/**
 * Verifies a BIP340 signature against a secp256k1 public key, whose x-only form BIP340 reads
 * (the parity of y is dropped), with libsecp256k1's static context, which allocates nothing,
 * after its self-test.
 *
 * @tparam Backend The backend, `backends::secp256k1`, the only one; another stops the build.
 * @tparam Signature `curves::secp256k1::schnorr_signature`; another type, bytes included, stops
 * the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included; a `crypto::prehashed` marker, or anything else, stops the build.
 * @param signing_scheme `crypto::schnorr`.
 * @param signature_value The signature; 64 bytes from a peer are made into one by
 * `curves::secp256k1::schnorr_signature::from_bytes`.
 * @param message_input The signed message, as given.
 * @param public_key The signer's public key: a key pair's `public_key()`.
 * @return Nothing; `invalid_signature` for a signature that does not verify.
 */
template <class Backend = default_backend_t<families::secp256k1>, class Signature, class Input>
[[nodiscard]] boost::system::result<void> verify(
    [[maybe_unused]] schnorr_t signing_scheme, Signature const& signature_value,
    Input const& message_input, curves::secp256k1::public_key const& public_key) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(detail::secp256k1_refuses_others<families::secp256k1, Backend>);
    return detail::secp256k1_verify_schnorr_key<Backend>(
        detail::checked_signature_bytes<curves::secp256k1::schnorr_signature, schnorr_t>(
            signature_value),
        message_input, detail::secp256k1_access::point(public_key));
}

}  // namespace webcpp::crypto

namespace webcpp::crypto::detail {

/**
 * A secp256k1 key pair signs with ECDSA over SHA-256.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool signs_with_v<curves::secp256k1::basic_keypair<Backend>, ecdsa_sha256_t> =
    true;

/**
 * A secp256k1 key pair signs with ECDSA over SHA-256 with the recovery id.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool
    signs_with_v<curves::secp256k1::basic_keypair<Backend>, ecdsa_sha256_recoverable_t> = true;

/**
 * A secp256k1 key pair signs with Ethereum's recoverable ECDSA over Keccak-256.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool
    signs_with_v<curves::secp256k1::basic_keypair<Backend>, ecdsa_keccak256_recoverable_t> = true;

/**
 * A secp256k1 key pair signs with BIP340's Schnorr.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
inline constexpr bool signs_with_v<curves::secp256k1::basic_keypair<Backend>, schnorr_t> = true;

/** A secp256k1 public key verifies ECDSA over SHA-256. */
template <>
inline constexpr bool verifies_with_v<curves::secp256k1::public_key, ecdsa_sha256_t> = true;

/** A secp256k1 public key verifies BIP340's Schnorr, through its x-only form. */
template <>
inline constexpr bool verifies_with_v<curves::secp256k1::public_key, schnorr_t> = true;

/**
 * A BIP340 x-only key, its 32 bytes, verifies `schnorr`: any bytes that convert to
 * `std::span<std::uint8_t const, 32>`, an array of 32 bytes or a span of that fixed size; its
 * backend is `void`, the primary `key_backend`'s.
 *
 * @tparam Key The public key's type.
 */
template <class Key>
    requires std::is_convertible_v<Key const&, std::span<std::uint8_t const, 32>>
inline constexpr bool verifies_with_v<Key, schnorr_t> = true;

/**
 * A secp256k1 key pair's signature under ECDSA over SHA-256, `curves::secp256k1::ecdsa_signature`.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::secp256k1::basic_keypair<Backend>, ecdsa_sha256_t> {
    /** The signature type. */
    using type = curves::secp256k1::ecdsa_signature;
};

/**
 * A secp256k1 key pair's signature under ECDSA over SHA-256 with the recovery id,
 * `curves::secp256k1::recoverable_signature`.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::secp256k1::basic_keypair<Backend>, ecdsa_sha256_recoverable_t> {
    /** The signature type. */
    using type = curves::secp256k1::recoverable_signature;
};

/**
 * A secp256k1 key pair's signature under Ethereum's recoverable ECDSA over Keccak-256,
 * `curves::secp256k1::recoverable_signature`, the type `ecdsa_sha256_recoverable` gives (design
 * R20): the bytes are the same, and the scheme is the input's hash.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::secp256k1::basic_keypair<Backend>, ecdsa_keccak256_recoverable_t> {
    /** The signature type. */
    using type = curves::secp256k1::recoverable_signature;
};

/**
 * A secp256k1 key pair's signature under BIP340's Schnorr, `curves::secp256k1::schnorr_signature`.
 *
 * @tparam Backend The key's backend.
 */
template <class Backend>
struct signature_of<curves::secp256k1::basic_keypair<Backend>, schnorr_t> {
    /** The signature type. */
    using type = curves::secp256k1::schnorr_signature;
};

/**
 * A secp256k1 public key's signature under ECDSA over SHA-256,
 * `curves::secp256k1::ecdsa_signature`.
 */
template <>
struct signature_of<curves::secp256k1::public_key, ecdsa_sha256_t> {
    /** The signature type. */
    using type = curves::secp256k1::ecdsa_signature;
};

/**
 * A secp256k1 public key's signature under BIP340's Schnorr,
 * `curves::secp256k1::schnorr_signature`.
 */
template <>
struct signature_of<curves::secp256k1::public_key, schnorr_t> {
    /** The signature type. */
    using type = curves::secp256k1::schnorr_signature;
};

/**
 * The signature of a BIP340 x-only key, its 32 bytes, under `schnorr`,
 * `curves::secp256k1::schnorr_signature`.
 *
 * @tparam Key The public key's type.
 */
template <class Key>
    requires std::is_convertible_v<Key const&, std::span<std::uint8_t const, 32>>
struct signature_of<Key, schnorr_t> {
    /** The signature type. */
    using type = curves::secp256k1::schnorr_signature;
};

/**
 * A secp256k1 key pair's backend.
 *
 * @tparam Backend The key pair's backend.
 */
template <class Backend>
struct key_backend<curves::secp256k1::basic_keypair<Backend>> {
    /** The backend. */
    using type = Backend;
};

/** A secp256k1 public key's backend, libsecp256k1, the curve's one. */
template <>
struct key_backend<curves::secp256k1::public_key> {
    /** The backend. */
    using type = backends::secp256k1;
};

/**
 * `crypto::verify` of ECDSA over SHA-256 against a secp256k1 public key is secp256k1's, so that
 * the catch-all steps aside.
 */
template <>
inline constexpr bool has_verifier_v<ecdsa_sha256_t, curves::secp256k1::public_key> = true;

/**
 * `crypto::verify` of `schnorr` against a secp256k1 public key is secp256k1's, so that the
 * catch-all steps aside.
 */
template <>
inline constexpr bool has_verifier_v<schnorr_t, curves::secp256k1::public_key> = true;

/**
 * `crypto::verify` of `schnorr` against 32 bytes is secp256k1's, so that the catch-all steps
 * aside.
 *
 * @tparam Key The public key's type.
 */
template <class Key>
    requires std::is_convertible_v<Key const&, std::span<std::uint8_t const, 32>>
inline constexpr bool has_verifier_v<schnorr_t, Key> = true;

}  // namespace webcpp::crypto::detail

// The key pair concepts (design D4), on the family's one backend, which this header includes: it
// signs and agrees.
static_assert(
    ::webcpp::crypto::keypair<
        ::webcpp::crypto::curves::secp256k1::basic_keypair<::webcpp::crypto::backends::secp256k1>>,
    "webcpp::crypto: secp256k1's key pair meets crypto::keypair.");
static_assert(
    ::webcpp::crypto::signing_keypair<
        ::webcpp::crypto::curves::secp256k1::basic_keypair<::webcpp::crypto::backends::secp256k1>>,
    "webcpp::crypto: secp256k1's key pair meets crypto::signing_keypair.");
static_assert(
    ::webcpp::crypto::agreement_keypair<
        ::webcpp::crypto::curves::secp256k1::basic_keypair<::webcpp::crypto::backends::secp256k1>>,
    "webcpp::crypto: secp256k1's key pair meets crypto::agreement_keypair.");

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_HPP
