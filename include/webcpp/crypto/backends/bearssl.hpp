// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend BearSSL: BearSSL's own C code, built from its sources by
 `/third_party//bearssl`. It serves `ciphers::gcm<aes128/192/256<backends::bearssl>>`,
 `ciphers::chacha20_poly1305<backends::bearssl>` and `curves::p256`, and has no block cipher.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
#define WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP

#include <webcpp/crypto/config.hpp>

// The first of BearSSL's three layers: a program that uses BearSSL
// without linking it stops here, with the line to write.
#ifndef WEBCPP_CRYPTO_HAS_BEARSSL
// clang-format off
#error "webcpp::crypto: the backend BearSSL is used and not linked. In the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto. (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
// clang-format on
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/error.hpp>

#include <bearssl.h>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#ifdef WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION
/** The configuration the canary names: a test's, here. */
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION
#elif defined(_WIN32)
/** The configuration the canary names: BearSSL's seeder on Windows, none. */
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION noseeder
#else
/** The configuration the canary names: BearSSL's seeder as third_party/Jamfile builds it. */
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION getentropy  // lint-world: a canary's name
#endif
/**
 * The canary's name (the link's second layer): src/canary_bearssl.c defines it in
 * the library, and every function that calls BearSSL reads it; on MSVC the linker also compares
 * the same three facts, the third layer.
 */
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY                            \
    WEBCPP_CRYPTO_DETAIL_CANARY(bearssl, WEBCPP_CRYPTO_BEARSSL_COMMIT, \
                                WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                       \
    "webcpp_crypto_backend_bearssl",                                           \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(bearssl, WEBCPP_CRYPTO_BEARSSL_COMMIT, \
                                        WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION))
#endif

// src/canary_bearssl.c defines the canary with a constant; this is its declaration.
// NOLINTNEXTLINE(bugprone-dynamic-static-initializers): a declaration, never initialised here
extern "C" const char WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY;

namespace webcpp::crypto::backends {

/** The backend BearSSL. @see "The backends", in the guide. */
struct bearssl {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "bearssl";
};

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto::detail {

/**
 * The CTR class: AES-NI, then POWER8, then the constant-time 64-bit code, which BearSSL would
 * not pick on wasm32 by itself (its default there is the 32-bit code, half as fast). The test
 * seam WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE keeps the constant-time code on every CPU.
 *
 * @return The class whose `init` expands a key into a `br_aes_gen_ctr_keys`.
 */
inline br_block_ctr_class const* bearssl_ctr() noexcept {
#ifndef WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE
    if (auto const* x86_impl = br_aes_x86ni_ctr_get_vtable()) {
        return x86_impl;
    }
    if (auto const* power8_impl = br_aes_pwr8_ctr_get_vtable()) {
        return power8_impl;
    }
#endif
    return &br_aes_ct64_ctr_vtable;
}

/**
 * The GHASH code: PCLMUL, then POWER8, then the constant-time 64-bit code.
 *
 * @return The function `br_gcm_init` is given.
 */
inline br_ghash bearssl_ghash() noexcept {
#ifndef WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE
    if (br_ghash const pclmul_ghash = br_ghash_pclmul_get()) {
        return pclmul_ghash;
    }
    if (br_ghash const power8_impl = br_ghash_pwr8_get()) {
        return power8_impl;
    }
#endif
    return &br_ghash_ctmul64;
}

/** GCM's state on BearSSL: the key schedule, the context and the direction, in the object. */
template <std::size_t KeySize>
struct gcm_state<backends::bearssl, KeySize> {
    /** The key schedule of the CTR class @ref bearssl_ctr picks. */
    br_aes_gen_ctr_keys keys;
    /** GCM's context, which points at `keys`. */
    br_gcm_context context;
    /** Whether the message in progress is a seal. */
    bool sealing;
};

/** GCM's work on BearSSL; BearSSL allocates nothing and never fails. */
template <std::size_t KeySize>
struct gcm_engine<backends::bearssl, KeySize> {
    /** The state it works on. */
    using state = gcm_state<backends::bearssl, KeySize>;

    /**
     * Expands the key and initialises the context on it.
     *
     * @param engine_state An empty state.
     * @param key_bytes `KeySize` bytes.
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        bearssl_ctr()->init(&engine_state.keys.vtable, key_bytes.data(), key_bytes.size());
        br_gcm_init(&engine_state.context, &engine_state.keys.vtable, bearssl_ghash());
        return {};
    }

    /**
     * Starts a message: the IV, then the whole additional data.
     *
     * @param engine_state A keyed state.
     * @param is_sealing Whether the message is sealed or opened.
     * @param iv_bytes 1 to 128 bytes.
     * @param additional_data_bytes Read whole before this returns.
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> start(
        state& engine_state, bool is_sealing, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        engine_state.sealing = is_sealing;
        br_gcm_reset(&engine_state.context, iv_bytes.data(), iv_bytes.size());
        br_gcm_aad_inject(&engine_state.context, additional_data_bytes.data(),
                          additional_data_bytes.size());
        br_gcm_flip(&engine_state.context);
        return {};
    }

    /**
     * Encrypts or decrypts the next bytes of the message in place.
     *
     * @param engine_state A state in a message.
     * @param data_bytes The bytes.
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> run(
        state& engine_state, std::span<std::uint8_t> data_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        br_gcm_run(&engine_state.context, engine_state.sealing ? 1 : 0, data_bytes.data(),
                   data_bytes.size());
        return {};
    }

    /**
     * Writes the tag of a sealed message.
     *
     * @param engine_state A state in a seal.
     * @param output_bytes The tag.
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> tag(
        state& engine_state, boost::hash2::digest<16>& output_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        br_gcm_get_tag(&engine_state.context, output_bytes.data());
        return {};
    }

    /**
     * Compares the tag of an opened message with `tag_bytes` in constant time.
     *
     * @param engine_state A state in an open.
     * @param tag_bytes The expected tag.
     * @return Nothing; `authentication_failed`.
     */
    [[nodiscard]] static boost::system::result<void> check(
        state& engine_state, std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // The verdict is public by design (a failed open is reported): declassified here,
        // where webcpp's code first branches on it, for the constant-time checks.
        // Not const: the branch below must read the variable again after the declassifying
        // client request, whose memory clobber reaches a mutable object only.
        // NOLINTNEXTLINE(misc-const-correctness): see above
        std::uint32_t tag_matches = br_gcm_check_tag(&engine_state.context, tag_bytes.data());
        WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&tag_matches, sizeof tag_matches);
        if (tag_matches != 1) {
            return error::authentication_failed;
        }
        return {};
    }

    /**
     * Moves the key into an empty state, and wipes the source. The context points at the key
     * schedule (`br_gcm_context::bctx`), so the schedule is copied and the destination's
     * context initialised again on it: a message in progress is abandoned.
     *
     * @param target_state An empty state.
     * @param source_state A keyed state, wiped.
     */
    static void move(state& target_state, state& source_state) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        target_state.keys = source_state.keys;
        br_gcm_init(&target_state.context, &target_state.keys.vtable, bearssl_ghash());
        target_state.sealing = false;
        reset(source_state);
    }

    /**
     * Wipes the message's state and initialises the context again on the kept schedule.
     *
     * @param engine_state A keyed state.
     */
    static void abandon(state& engine_state) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        wipe_object(engine_state.context);
        br_gcm_init(&engine_state.context, &engine_state.keys.vtable, bearssl_ghash());
        engine_state.sealing = false;
    }

    /**
     * Wipes the key and the message; the state is empty.
     *
     * @param engine_state Any state.
     */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state); }
};

/**
 * ChaCha20's code: SSE2's where the CPU and the build have it, else the constant-time portable
 * code. The test seam WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE keeps the portable code on every
 * CPU. Both are constant time (inc/bearssl_block.h).
 *
 * @return The function `br_poly1305_run` is given.
 */
inline br_chacha20_run bearssl_chacha20() noexcept {
#ifndef WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE
    if (br_chacha20_run const sse2_impl = br_chacha20_sse2_get()) {
        return sse2_impl;
    }
#endif
    return &br_chacha20_ct_run;
}

/**
 * Poly1305's code: the 64-bit multiplication's where the compiler has 128-bit integers, else the
 * constant-time 32-bit multiplication's. The test seam WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE keeps
 * the latter on every target. Both are constant time (inc/bearssl_block.h).
 *
 * @return The function that runs ChaCha20-Poly1305.
 */
inline br_poly1305_run bearssl_poly1305() noexcept {
#ifndef WEBCPP_CRYPTO_DETAIL_BEARSSL_PORTABLE
    if (br_poly1305_run const ctmulq_impl = br_poly1305_ctmulq_get()) {
        return ctmulq_impl;
    }
#endif
    return &br_poly1305_ctmul_run;
}

/** ChaCha20-Poly1305's state on BearSSL: the key, in the object, since BearSSL takes it per call.
 */
template <>
struct aead_state<families::chacha20_poly1305, backends::bearssl> {
    /** The key. */
    std::array<std::uint8_t, 32> key{};
};

/**
 * ChaCha20-Poly1305 on BearSSL: one function over the whole message, which encrypts or decrypts
 * and computes the tag (inc/bearssl_block.h, `br_poly1305_run`). BearSSL leaves the tag's check
 * to its caller: `equal` does it. BearSSL allocates nothing and never fails.
 */
template <>
struct aead_engine<families::chacha20_poly1305, backends::bearssl> {
    /** The state. */
    using state = aead_state<families::chacha20_poly1305, backends::bearssl>;

    /**
     * Keeps the key.
     *
     * @param engine_state An empty state.
     * @param key_bytes 32 bytes (`aead` has checked their size).
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> init(
        state& engine_state, std::span<std::uint8_t const> key_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        std::ranges::copy(key_bytes, engine_state.key.begin());
        return {};
    }

    /**
     * Encrypts `data_bytes` in place and writes the tag. BearSSL reads the nonce before it
     * writes a byte of the data, and the additional data after it encrypts (`aead` forbids
     * their overlap).
     *
     * @param engine_state A keyed state.
     * @param iv_bytes 12 bytes.
     * @param additional_data_bytes Authenticated, not encrypted.
     * @param data_bytes The message.
     * @param tag_bytes The tag.
     * @return Nothing.
     */
    [[nodiscard]] static boost::system::result<void> seal(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data_bytes, std::span<std::uint8_t> data_bytes,
        boost::hash2::digest<16>& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        bearssl_poly1305()(engine_state.key.data(), iv_bytes.data(), data_bytes.data(),
                           data_bytes.size(), additional_data_bytes.data(),
                           additional_data_bytes.size(), tag_bytes.data(), bearssl_chacha20(), 1);
        return {};
    }

    /**
     * Decrypts `data_bytes` in place, then compares the tag it computed with `tag_bytes` in
     * constant time; `aead` zeroes the data when they differ.
     *
     * @param engine_state A keyed state.
     * @param iv_bytes 12 bytes.
     * @param additional_data_bytes The additional data of the seal.
     * @param data_bytes The ciphertext.
     * @param tag_bytes The expected tag.
     * @return Nothing; `authentication_failed`.
     */
    [[nodiscard]] static boost::system::result<void> open(
        state& engine_state, std::span<std::uint8_t const> iv_bytes,
        std::span<std::uint8_t const> additional_data_bytes, std::span<std::uint8_t> data_bytes,
        std::array<std::uint8_t, 16> const& tag_bytes) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        std::array<std::uint8_t, 16> computed_tag{};
        bearssl_poly1305()(engine_state.key.data(), iv_bytes.data(), data_bytes.data(),
                           data_bytes.size(), additional_data_bytes.data(),
                           additional_data_bytes.size(), computed_tag.data(), bearssl_chacha20(),
                           0);
        // The verdict is public by design (a failed open is reported): declassified here,
        // where webcpp's code first branches on it, for the constant-time checks.
        // Not const: the branch below must read the variable again after the declassifying
        // client request, whose memory clobber reaches a mutable object only.
        // NOLINTNEXTLINE(misc-const-correctness): see above
        bool tag_matches = equal(computed_tag, tag_bytes);
        WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&tag_matches, sizeof tag_matches);
        wipe(computed_tag.data(), computed_tag.size());
        if (!tag_matches) {
            return error::authentication_failed;
        }
        return {};
    }

    /**
     * Moves the key into an empty state, and wipes the source.
     *
     * @param target_state An empty state.
     * @param source_state A keyed state, wiped.
     */
    static void move(state& target_state, state& source_state) noexcept {
        target_state.key = source_state.key;
        wipe_object(source_state.key);
    }

    /**
     * Wipes the key; the state is empty.
     *
     * @param engine_state Any state.
     */
    static void reset(state& engine_state) noexcept { wipe_object(engine_state.key); }
};

/**
 * BearSSL's P-256 code for this target: natively the 64-bit multiplications of br_ec_p256_m62
 * where BearSSL has them (__int128, or MSVC's _umul128), else br_ec_p256_m31; on WebAssembly
 * br_ec_p256_m31 always, since wasm32's 128-bit product is a compiler-rt call whose timing nobody
 * states (design D36). Each is constant time (BearSSL's documentation).
 *
 * @return The implementation of the curve's arithmetic.
 */
[[nodiscard]] inline br_ec_impl const* bearssl_p256() noexcept {
#ifndef WEBCPP_CRYPTO_WEBASSEMBLY
    if (br_ec_impl const* wide = br_ec_p256_m62_get()) {
        return wide;
    }
#endif
    return &br_ec_p256_m31;
}

/** A P-256 key pair's state on BearSSL: the scalar and the point, in the object. */
template <>
struct p_curve_state<families::p256, backends::bearssl> {
    /** The secret scalar d, big-endian. */
    std::array<std::uint8_t, 32> scalar{};
    /** The public point d * G, SEC 1's uncompressed form. */
    std::array<std::uint8_t, 65> point{};
};

/**
 * P-256 on BearSSL: the point of a key pair computed once by `mulgen`, a public point checked
 * by BearSSL's decoding, ECDSA with RFC 6979's nonce and its DER conversions, ECDH's raw x
 * coordinate. BearSSL allocates nothing; its curve code never fails on a valid input.
 */
template <>
struct p_curve_engine<families::p256, backends::bearssl> {
    /** The state. */
    using state = p_curve_state<families::p256, backends::bearssl>;

    /**
     * Keeps the scalar and computes its public point.
     *
     * @param keyed An empty state.
     * @param scalar 32 bytes, 0 < d < n (the family's header has checked them).
     * @return Nothing; `backend_failure`, which a valid scalar cannot cause.
     */
    [[nodiscard]] static boost::system::result<void> make(
        state& keyed, std::span<std::uint8_t const, 32> scalar) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        std::ranges::copy(scalar, keyed.scalar.begin());
        if (bearssl_p256()->mulgen(keyed.point.data(), keyed.scalar.data(), keyed.scalar.size(),
                                   BR_EC_secp256r1) != keyed.point.size()) {
            reset(keyed);
            return error::backend_failure;
        }
        return {};
    }

    /**
     * Whether an uncompressed point is on the curve, its coordinates below p.
     *
     * @param point 65 bytes, whose first byte is 04 (the family's header has checked it).
     * @return Whether BearSSL decodes it.
     */
    [[nodiscard]] static bool valid_point(std::span<std::uint8_t const, 65> point) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // BearSSL decodes, and so checks, a point only to multiply it: by 1 it comes back as it
        // was, re-encoded, when its coordinates are below p and on the curve (design D36).
        std::array<std::uint8_t, 65> decoded{};
        std::ranges::copy(point, decoded.begin());
        constexpr std::array<std::uint8_t, 1> one{1};
        return bearssl_p256()->mul(decoded.data(), decoded.size(), one.data(), one.size(),
                                   BR_EC_secp256r1) == 1 &&
               std::ranges::equal(decoded, point);
    }

    /**
     * Signs a digest with ECDSA and RFC 6979's nonce, S as BearSSL computes it (design D36).
     *
     * @param keyed A keyed state.
     * @param digest The 32-byte SHA-256 digest.
     * @param output 64 bytes, r then s.
     * @return Nothing; `backend_failure`, which a valid key cannot cause.
     */
    [[nodiscard]] static boost::system::result<void> sign(
        state const& keyed, std::span<std::uint8_t const, 32> digest,
        std::span<std::uint8_t, 64> output) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // BearSSL's struct is not const-correct: it only reads the scalar.
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): see above
        auto* const scalar = const_cast<unsigned char*>(keyed.scalar.data());
        br_ec_private_key const key{
            .curve = BR_EC_secp256r1,
            .x = scalar,
            .xlen = keyed.scalar.size(),
        };
        // RFC 6979's nonce, from HMAC-DRBG over SHA-256: br_sha256_vtable is the hash of the
        // nonce's derivation, which RFC 6979 makes the digest's own. No random number is drawn.
        if (br_ecdsa_i31_sign_raw(bearssl_p256(), &br_sha256_vtable, digest.data(), &key,
                                  output.data()) != output.size()) {
            return error::backend_failure;
        }
        return {};
    }

    /**
     * ECDH: the peer's point multiplied by the scalar, and the product's x coordinate.
     *
     * @param keyed A keyed state.
     * @param peer The peer's uncompressed point, valid (its public key was made by BearSSL's
     * decoding).
     * @param output 32 bytes, a `secret<32>`'s.
     * @return Nothing; `backend_failure`, which a valid point and a scalar in range cannot cause.
     */
    [[nodiscard]] static boost::system::result<void> ecdh_x(
        state const& keyed, std::span<std::uint8_t const, 65> peer,
        std::span<std::uint8_t, 32> output) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // BearSSL multiplies in place: the copy becomes d * Q, uncompressed, and is wiped after.
        std::array<std::uint8_t, 65> shared{};
        std::ranges::copy(peer, shared.begin());
        // BearSSL's verdict folds in its own check of the scalar's range, so a constant-time
        // checker holds it secret; whether a valid point and a valid scalar multiply is public.
        // Not const: the branch reads it again after the mark (detail/declassify.hpp's tip).
        // NOLINTNEXTLINE(misc-const-correctness): see above
        std::uint32_t multiplied =
            bearssl_p256()->mul(shared.data(), shared.size(), keyed.scalar.data(),
                                keyed.scalar.size(), BR_EC_secp256r1);
        WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&multiplied, sizeof multiplied);
        if (multiplied != 1) {
            wipe_object(shared);
            return error::backend_failure;  // a validated point and a scalar in range never fail
        }
        std::size_t x_size = 0;
        std::size_t const x_offset = bearssl_p256()->xoff(BR_EC_secp256r1, &x_size);
        std::ranges::copy(std::span<std::uint8_t const>(shared).subspan(x_offset, x_size),
                          output.begin());
        wipe_object(shared);
        return {};
    }

    /**
     * Verifies an ECDSA signature; a high S is accepted (design D36).
     *
     * @param point The public key's uncompressed point, valid.
     * @param digest The 32-byte SHA-256 digest.
     * @param signature 64 bytes, r then s, each in range (the family's header has checked them).
     * @return Whether the signature verifies.
     */
    [[nodiscard]] static bool verify(std::span<std::uint8_t const, 65> point,
                                     std::span<std::uint8_t const, 32> digest,
                                     std::span<std::uint8_t const, 64> signature) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // BearSSL's struct holds a pointer to non-const bytes, which it only reads: a copy keeps
        // the key's own bytes const without a cast.
        std::array<std::uint8_t, 65> key_point{};
        std::ranges::copy(point, key_point.begin());
        br_ec_public_key const key{
            .curve = BR_EC_secp256r1,
            .q = key_point.data(),
            .qlen = key_point.size(),
        };
        return br_ecdsa_i31_vrfy_raw(bearssl_p256(), digest.data(), digest.size(), &key,
                                     signature.data(), signature.size()) == 1;
    }

    /**
     * Encodes a signature as strict DER.
     *
     * @param signature 64 bytes, r then s, each in range (the family's header has checked them).
     * @param output 72 bytes, room for the longest encoding.
     * @return The encoding's length, at most 72: 2 + 2 * (2 + 33).
     */
    [[nodiscard]] static std::size_t to_der(std::span<std::uint8_t const, 64> signature,
                                            std::span<std::uint8_t, 72> output) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // In place, and "by no more than 9 bytes" larger (bearssl_ec.h): room for 64 + 9.
        std::array<std::uint8_t, 64 + 9> work{};
        std::ranges::copy(signature, work.begin());
        std::size_t const length = br_ecdsa_raw_to_asn1(work.data(), signature.size());
        std::ranges::copy(std::span<std::uint8_t const>(work).first(length), output.begin());
        return length;
    }

    /**
     * Decodes a strict DER signature: BearSSL's decoder, then the re-encoding compared with the
     * input, since BearSSL accepts a few forms strict DER refuses.
     *
     * @param der The encoding, not empty.
     * @param output 64 bytes, r then s, padded to 32 bytes each; the caller keeps them only on
     * success and checks their range.
     * @return Whether the input is strict DER of two integers of at most 32 bytes.
     */
    [[nodiscard]] static bool from_der(std::span<std::uint8_t const> der,
                                       std::span<std::uint8_t, 64> output) noexcept {
        WEBCPP_CRYPTO_DETAIL_P_CURVE_ENGINE_ENTERED();
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        constexpr std::size_t longest = 72;
        if (der.size() > longest) {
            return false;
        }
        // In place, and up to twice the source's length (bearssl_ec.h): room for 2 * 72.
        std::array<std::uint8_t, 2 * longest> work{};
        std::ranges::copy(der, work.begin());
        // BearSSL strips the integers' leading zeros and writes r and s at the longer one's
        // length (ecdsa_atr.c), so a raw form shorter than 64 bytes is padded back to 32 each.
        std::size_t const raw_size = br_ecdsa_asn1_to_raw(work.data(), der.size());
        std::size_t const half = raw_size / 2;
        if (raw_size == 0 || half > 32) {
            return false;
        }
        std::array<std::uint8_t, 64 + 9> raw{};
        std::ranges::copy(std::span<std::uint8_t const>(work).first(half),
                          raw.begin() + static_cast<std::ptrdiff_t>(32 - half));
        std::ranges::copy(std::span<std::uint8_t const>(work).subspan(half, half),
                          raw.begin() + static_cast<std::ptrdiff_t>(64 - half));
        std::ranges::copy(std::span<std::uint8_t const>(raw).first<64>(), output.begin());
        // BearSSL's decoder accepts a long SEQUENCE length, needless zero bytes and a negative
        // integer; strict DER is what re-encodes to the same bytes (design D12).
        std::size_t const length = br_ecdsa_raw_to_asn1(raw.data(), 64);
        return length == der.size() &&
               std::ranges::equal(std::span<std::uint8_t const>(raw).first(length), der);
    }

    /**
     * Copies the public point; no BearSSL call.
     *
     * @param keyed A keyed state.
     * @param output 65 bytes.
     */
    static void public_point(state const& keyed, std::span<std::uint8_t, 65> output) noexcept {
        std::ranges::copy(keyed.point, output.begin());
    }

    /**
     * Copies the secret scalar; no BearSSL call.
     *
     * @param keyed A keyed state.
     * @param output 32 bytes, a `secret<32>`'s.
     */
    static void scalar(state const& keyed, std::span<std::uint8_t, 32> output) noexcept {
        std::ranges::copy(keyed.scalar, output.begin());
    }

    /**
     * Wipes the scalar and the point; the state is empty.
     *
     * @param keyed Any state.
     */
    static void reset(state& keyed) noexcept {
        wipe_object(keyed.scalar);
        wipe_object(keyed.point);
    }
};

/**
 * BearSSL has no AES block cipher: its state is empty, so `ciphers::aes256<backends::bearssl>` is
 * complete, and `ciphers::gcm<aes256<backends::bearssl>>` can read its key size.
 */
template <std::size_t KeySize>
struct block_state<backends::bearssl, KeySize> {};

/**
 * BearSSL's refusal of the block cipher. The assertions sit in member
 * templates, which only `make`, `encrypt` and `decrypt` instantiate: the class's moves and
 * destructor, which `ciphers::gcm<aes256<backends::bearssl>>` needs, never fire them.
 */
template <std::size_t KeySize>
struct block_engine<backends::bearssl, KeySize> {
    /** The empty state. */
    using state = block_state<backends::bearssl, KeySize>;

    /**
     * Stops the compile with the backends that export the block cipher.
     *
     * @tparam Never Always false: the assertion depends on it, so it fires only when a
     * caller instantiates this.
     */
    template <bool Never = false>
    static void refuse() noexcept {
        // clang-format off
        static_assert(Never || KeySize != 16, "webcpp::crypto: ciphers::aes128<backends::bearssl>: BearSSL exports AES only inside its modes, with no block cipher. Name a backend that exports it, as in ciphers::aes128<backends::ctaes> or ciphers::aes128<backends::openssl>, and add its library to the program's Jamfile.");
        static_assert(Never || KeySize != 24, "webcpp::crypto: ciphers::aes192<backends::bearssl>: BearSSL exports AES only inside its modes, with no block cipher. Name a backend that exports it, as in ciphers::aes192<backends::ctaes> or ciphers::aes192<backends::openssl>, and add its library to the program's Jamfile.");
        static_assert(Never || KeySize != 32, "webcpp::crypto: ciphers::aes256<backends::bearssl>: BearSSL exports AES only inside its modes, with no block cipher. Name a backend that exports it, as in ciphers::aes256<backends::ctaes> or ciphers::aes256<backends::openssl>, and add its library to the program's Jamfile.");
        // clang-format on
    }

    /**
     * Refused (see @ref refuse).
     *
     * @tparam Never Always false.
     * @return Never returns: the compile stops.
     */
    template <bool Never = false>
    [[nodiscard]] static boost::system::result<void> init(
        state& /*engine_state*/, std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        refuse<Never>();
        return error::backend_failure;
    }

    /**
     * Refused (see @ref refuse).
     *
     * @tparam Never Always false.
     * @return Never returns: the compile stops.
     */
    template <bool Never = false>
    [[nodiscard]] static boost::system::result<void> encrypt(
        state& /*engine_state*/, std::span<std::uint8_t> /*block_bytes*/) noexcept {
        refuse<Never>();
        return error::backend_failure;
    }

    /**
     * Refused (see @ref refuse).
     *
     * @tparam Never Always false.
     * @return Never returns: the compile stops.
     */
    template <bool Never = false>
    [[nodiscard]] static boost::system::result<void> decrypt(
        state& /*engine_state*/, std::span<std::uint8_t> /*block_bytes*/) noexcept {
        refuse<Never>();
        return error::backend_failure;
    }

    /** Nothing to move: the state is empty. */
    static void move(state& /*target_state*/, state& /*source_state*/) noexcept {}

    /** Nothing to wipe: the state is empty. */
    static void reset(state& /*engine_state*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_HAS_BEARSSL
#endif  // WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
