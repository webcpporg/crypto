// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend BearSSL: BearSSL's own C code, built from its sources by
 `/third_party//bearssl`. It serves `ciphers::gcm<aes128/192/256<backends::bearssl>>`, and has no
 block cipher.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
#define WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP

#include <webcpp/crypto/config.hpp>

// The first of BearSSL's three layers (spec section 4.3): a program that uses BearSSL
// without linking it stops here, with the line to write.
#ifndef WEBCPP_CRYPTO_HAS_BEARSSL
// clang-format off
#if defined(WEBCPP_CRYPTO_DETAIL_NONE_LINKED) && defined(WEBCPP_CRYPTO_WEBASSEMBLY)
#error "webcpp::crypto: no backend is linked. On WebAssembly the backend is BearSSL: in the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//bearssl ; (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#elif defined(WEBCPP_CRYPTO_DETAIL_NONE_LINKED)
#error "webcpp::crypto: no backend is linked. In the program's Jamfile, add /webcpp/crypto//openssl (OpenSSL built from source) or /third_party//bearssl (built from source) beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//openssl ; (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto, or define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#else
#error "webcpp::crypto: the backend BearSSL is used and not linked. In the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, or, with /webcpp/crypto//openssl linked, select OpenSSL with <define>WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL. (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#endif
// clang-format on
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/declassify.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <bearssl.h>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

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
 * The canary's name (spec section 4.3, the second layer): src/canary_bearssl.c defines it in
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

/** The backend BearSSL (spec section 3.2). */
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
    if (auto const* x86 = br_aes_x86ni_ctr_get_vtable()) {
        return x86;
    }
    if (auto const* power = br_aes_pwr8_ctr_get_vtable()) {
        return power;
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
    if (br_ghash const pclmul = br_ghash_pclmul_get()) {
        return pclmul;
    }
    if (br_ghash const power = br_ghash_pwr8_get()) {
        return power;
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

/** GCM's work on BearSSL (spec section 3.2); BearSSL allocates nothing and never fails. */
template <std::size_t KeySize>
struct gcm_engine<backends::bearssl, KeySize> {
    /** The state it works on. */
    using state = gcm_state<backends::bearssl, KeySize>;

    /**
     * Expands the key and initialises the context on it.
     *
     * @param s An empty state.
     * @param key `KeySize` bytes.
     * @return Nothing.
     */
    static boost::system::result<void> init(state& s, std::span<std::uint8_t const> key) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        bearssl_ctr()->init(&s.keys.vtable, key.data(), key.size());
        br_gcm_init(&s.context, &s.keys.vtable, bearssl_ghash());
        return {};
    }

    /**
     * Starts a message: the IV, then the whole additional data.
     *
     * @param s A keyed state.
     * @param sealing Whether the message is sealed or opened.
     * @param iv 1 to 128 bytes.
     * @param additional_data Read whole before this returns.
     * @return Nothing.
     */
    static boost::system::result<void> start(
        state& s, bool sealing, std::span<std::uint8_t const> iv,
        std::span<std::uint8_t const> additional_data) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        s.sealing = sealing;
        br_gcm_reset(&s.context, iv.data(), iv.size());
        br_gcm_aad_inject(&s.context, additional_data.data(), additional_data.size());
        br_gcm_flip(&s.context);
        return {};
    }

    /**
     * Encrypts or decrypts the next bytes of the message in place.
     *
     * @param s A state in a message.
     * @param data The bytes.
     * @return Nothing.
     */
    static boost::system::result<void> run(state& s, std::span<std::uint8_t> data) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        br_gcm_run(&s.context, s.sealing ? 1 : 0, data.data(), data.size());
        return {};
    }

    /**
     * Writes the tag of a sealed message.
     *
     * @param s A state in a seal.
     * @param out The tag.
     * @return Nothing.
     */
    static boost::system::result<void> tag(state& s, boost::hash2::digest<16>& out) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        br_gcm_get_tag(&s.context, out.data());
        return {};
    }

    /**
     * Compares the tag of an opened message with `tag` in constant time.
     *
     * @param s A state in an open.
     * @param tag The expected tag.
     * @return Nothing; `authentication_failed`.
     */
    static boost::system::result<void> check(state& s,
                                             std::array<std::uint8_t, 16> const& tag) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        // The verdict is public by design (a failed open is reported): declassified here,
        // where webcpp's code first branches on it, for the constant-time checks (Task 20).
        // Not const (n1): the branch below must read the variable again after the declassifying
        // client request, whose memory clobber reaches a mutable object only.
        // NOLINTNEXTLINE(misc-const-correctness): see above
        std::uint32_t matches = br_gcm_check_tag(&s.context, tag.data());
        WEBCPP_CRYPTO_DETAIL_DECLASSIFY(&matches, sizeof matches);
        if (matches != 1) {
            return error::authentication_failed;
        }
        return {};
    }

    /**
     * Moves the key into an empty state, and wipes the source. The context points at the key
     * schedule (`br_gcm_context::bctx`), so the schedule is copied and the destination's
     * context initialised again on it: a message in progress is abandoned.
     *
     * @param to An empty state.
     * @param from A keyed state, wiped.
     */
    static void move(state& to, state& from) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        to.keys = from.keys;
        br_gcm_init(&to.context, &to.keys.vtable, bearssl_ghash());
        to.sealing = false;
        reset(from);
    }

    /**
     * Wipes the message's state and initialises the context again on the kept schedule.
     *
     * @param s A keyed state.
     */
    static void abandon(state& s) noexcept {
        read_canary(WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY);
        wipe_object(s.context);
        br_gcm_init(&s.context, &s.keys.vtable, bearssl_ghash());
        s.sealing = false;
    }

    /**
     * Wipes the key and the message; the state is empty.
     *
     * @param s Any state.
     */
    static void reset(state& s) noexcept { wipe_object(s); }
};

/**
 * BearSSL has no AES block cipher: its state is empty, so `ciphers::aes256<backends::bearssl>` is
 * complete, and `ciphers::gcm<aes256<backends::bearssl>>` can read its key size.
 */
template <std::size_t KeySize>
struct block_state<backends::bearssl, KeySize> {};

/**
 * BearSSL's refusal of the block cipher (spec section 2.3). The assertions sit in member
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
    static boost::system::result<void> init(state& /*s*/,
                                            std::span<std::uint8_t const> /*key*/) noexcept {
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
    static boost::system::result<void> encrypt(state& /*s*/,
                                               std::span<std::uint8_t> /*blocks*/) noexcept {
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
    static boost::system::result<void> decrypt(state& /*s*/,
                                               std::span<std::uint8_t> /*blocks*/) noexcept {
        refuse<Never>();
        return error::backend_failure;
    }

    /** Nothing to move: the state is empty. */
    static void move(state& /*to*/, state& /*from*/) noexcept {}

    /** Nothing to wipe: the state is empty. */
    static void reset(state& /*s*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_HAS_BEARSSL
#endif  // WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
