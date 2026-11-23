// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 secp256k1's MuSig2 on libsecp256k1 (BIP 327): many signers' keys aggregated into one x-only
 key, and their two rounds, nonces then partial signatures, into one BIP 340 signature under it.
 A secret nonce is consumed by the partial signature it makes.

 @see "MuSig2: many signers, one signature", in the guide's secp256k1 chapter.
*/
#ifndef WEBCPP_CRYPTO_CURVES_SECP256K1_MUSIG_HPP
#define WEBCPP_CRYPTO_CURVES_SECP256K1_MUSIG_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/signature.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: the nonce's session randomness

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

namespace webcpp::crypto::detail {

/**
 * What a MuSig2 secret nonce holds: libsecp256k1's secret nonce first, then the compressed key
 * of the key pair it was made for, and whether it may still sign.
 */
struct secp256k1_nonce_state {
    /** libsecp256k1's secret nonce: its magic, two secret scalars and the signer's point. */
    secp256k1_musig_secnonce nonce_value{};
    /** The signer's public key, SEC1 compressed, public. */
    std::array<std::uint8_t, 33> signer_key{};
    /** True from `nonce_gen` until a partial signature, a move or the destructor uses it. */
    bool fresh = false;
};

/**
 * The refusal of a backend other than libsecp256k1 by the family `families::secp256k1_musig`: the
 * functions of `curves/secp256k1/musig.hpp`.
 *
 * @tparam Backend The backend named.
 */
template <class Backend>
struct secp256k1_refusal<families::secp256k1_musig, Backend, false> {
    WEBCPP_CRYPTO_DETAIL_REFUSE_SECP256K1_MUSIG(Backend);
};

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::curves::secp256k1::musig {

/** The size of a signer's public nonce: two compressed points. */
inline constexpr std::size_t public_nonce_size = 66;

/** The size of an aggregate nonce: two compressed points, each 33 zero bytes at infinity. */
inline constexpr std::size_t aggregate_nonce_size = 66;

/** The size of a partial signature: a scalar below the group order. */
inline constexpr std::size_t partial_signature_size = 32;

/**
 * The signers' aggregate key and what signing needs of it (libsecp256k1's keyagg cache), with
 * the tweaks a protocol applies to it: public data, copied freely, made only by
 * `key_aggregate`.
 */
class aggregate_key {
public:
    /**
     * The BIP 340 x-only key the final signature verifies under.
     *
     * @return 32 bytes, the tweaks included.
     */
    [[nodiscard]] std::array<std::uint8_t, 32> xonly_public_key() const noexcept {
        detail::timing_guard const timing_scope;
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        public_key full_key = full_public_key();
        secp256k1_xonly_pubkey xonly_key{};
        std::array<std::uint8_t, 32> output_bytes{};
        // A valid point always has an x-only form: libsecp256k1 returns 1.
        static_cast<void>(secp256k1_xonly_pubkey_from_pubkey(
            secp256k1_context_static, &xonly_key, nullptr,
            &webcpp::crypto::detail::secp256k1_access::point(full_key)));
        static_cast<void>(secp256k1_xonly_pubkey_serialize(secp256k1_context_static,
                                                           output_bytes.data(), &xonly_key));
        return output_bytes;
    }

    /**
     * The aggregate as a full point (`secp256k1_musig_pubkey_get`), which a plain tweak acts on.
     *
     * @return The key, the tweaks included.
     */
    [[nodiscard]] public_key full_public_key() const noexcept {
        detail::timing_guard const timing_scope;
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        using access = webcpp::crypto::detail::secp256k1_access;
        public_key full_key = access::make_public_key();
        // The cache is valid, made by key_aggregate: libsecp256k1 returns 1. The status is named
        // and dropped, since GCC's warn_unused_result does not yield to a cast to void.
        int const get_status = secp256k1_musig_pubkey_get(secp256k1_context_static,
                                                          &access::point(full_key), &native_value_);
        static_cast<void>(get_status);
        return full_key;
    }

    /**
     * Adds t times G as a plain tweak (BIP 327's ApplyTweak, is_xonly false,
     * `secp256k1_musig_pubkey_ec_tweak_add`).
     *
     * @param tweak_bytes The 32-byte tweak t, a big-endian scalar.
     * @return Nothing; `invalid_secret_key` for a tweak not below the group order or a result
     * at infinity, after which the key is unchanged.
     */
    [[nodiscard]] boost::system::result<void> tweak_add(
        std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
        detail::timing_guard const timing_scope;
        return tweaked(tweak_bytes, secp256k1_musig_pubkey_ec_tweak_add);
    }

    /**
     * Adds t times G as an x-only tweak (BIP 327's ApplyTweak, is_xonly true,
     * `secp256k1_musig_pubkey_xonly_tweak_add`), as Taproot tweaks an output key.
     *
     * @param tweak_bytes The 32-byte tweak t, a big-endian scalar.
     * @return Nothing; `invalid_secret_key` for a tweak not below the group order or a result
     * at infinity, after which the key is unchanged.
     */
    [[nodiscard]] boost::system::result<void> tweak_xonly_add(
        std::span<std::uint8_t const, 32> tweak_bytes) noexcept {
        detail::timing_guard const timing_scope;
        return tweaked(tweak_bytes, secp256k1_musig_pubkey_xonly_tweak_add);
    }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    aggregate_key() noexcept = default;

    /**
     * The cache tweaked by libsecp256k1, which leaves it as it was when it refuses.
     *
     * @param tweak_bytes The 32-byte tweak.
     * @param tweak_function libsecp256k1's plain or x-only tweak.
     * @return Nothing; `invalid_secret_key`.
     */
    [[nodiscard]] boost::system::result<void> tweaked(
        std::span<std::uint8_t const, 32> tweak_bytes,
        int (*tweak_function)(secp256k1_context const*, secp256k1_pubkey*,
                              secp256k1_musig_keyagg_cache*, unsigned char const*)) noexcept {
        webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
        secp256k1_selftest();
        if (tweak_function(secp256k1_context_static, nullptr, &native_value_, tweak_bytes.data()) ==
            0) {
            return error::invalid_secret_key;
        }
        return {};
    }

    secp256k1_musig_keyagg_cache native_value_{};
};

/**
 * A signer's public nonce, parsed (libsecp256k1's pubnonce): public, copied freely, made only
 * by `nonce_gen` and `parse_public_nonce`.
 */
class public_nonce {
private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    public_nonce() noexcept = default;

    secp256k1_musig_pubnonce native_value_{};
};

/**
 * The sum of the signers' public nonces, parsed (libsecp256k1's aggnonce): public, copied
 * freely, made only by `nonce_aggregate` and `parse_aggregate_nonce`.
 */
class aggregate_nonce {
private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    aggregate_nonce() noexcept = default;

    secp256k1_musig_aggnonce native_value_{};
};

/**
 * The session of one message (libsecp256k1's session): the final nonce and the challenge, public,
 * copied freely, made only by `nonce_process`.
 */
class session {
private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    session() noexcept = default;

    secp256k1_musig_session native_value_{};
};

/**
 * One signer's partial signature, parsed (libsecp256k1's partial_sig): public, copied freely,
 * made only by `partial_sign` and `parse_partial_signature`.
 */
class partial_signature {
private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    partial_signature() noexcept = default;

    secp256k1_musig_partial_sig native_value_{};
};

/**
 * A signer's secret nonce: move-only, wiped on move and destruction, made only by `nonce_gen`.
 *
 * It is consumed by `partial_sign`, which takes it by value, so that a nonce cannot be passed to a
 * second signature without an explicit `std::move` of an object already moved from (which
 * `partial_sign` refuses with `invalid_state`). Reusing a nonce in two signatures reveals the
 * secret key.
 */
class secret_nonce {
public:
    /**
     * Moves the nonce; the source is wiped and signs nothing.
     *
     * @param moved_source The source, empty afterwards.
     */
    secret_nonce(secret_nonce&& moved_source) noexcept : native_value_(moved_source.native_value_) {
        moved_source.release();
    }

    /**
     * Moves over this nonce, which is wiped first.
     *
     * @param moved_source The source, empty afterwards.
     * @return This nonce.
     */
    secret_nonce& operator=(secret_nonce&& moved_source) noexcept {
        if (this != &moved_source) {
            release();
            native_value_ = moved_source.native_value_;
            moved_source.release();
        }
        return *this;
    }

    /** Not copyable: a copy could sign a second message, which reveals the secret key. */
    secret_nonce(secret_nonce const&) = delete;
    /** Not copyable: a copy could sign a second message, which reveals the secret key. */
    secret_nonce& operator=(secret_nonce const&) = delete;

    /** Wipes the nonce. */
    ~secret_nonce() { release(); }

private:
    friend struct webcpp::crypto::detail::secp256k1_access;

    secret_nonce() noexcept = default;

    void release() noexcept { webcpp::crypto::detail::wipe_object(native_value_); }

    webcpp::crypto::detail::secp256k1_nonce_state native_value_{};
};

/** What `nonce_gen` returns: the secret nonce to keep, the public nonce to send. */
struct nonce_pair {
    /** The secret nonce, which this signer's `partial_sign` consumes. */
    secret_nonce secret_part;
    /** The public nonce, sent to every other signer. */
    public_nonce public_part;
};

/**
 * The workspace `key_aggregate`, `nonce_aggregate` and `partial_signature_aggregate` need for
 * `item_count` items, in bytes.
 *
 * @param item_count The number of keys, nonces or partial signatures.
 * @return One array of `item_count` pointers and one `alignof(std::max_align_t)` of padding.
 */
[[nodiscard]] constexpr std::size_t workspace_size(std::size_t item_count) noexcept {
    return (item_count * sizeof(void const*)) + alignof(std::max_align_t);
}

/**
 * Aggregates the signers' keys in the order given (`secp256k1_musig_pubkey_agg`).
 *
 * Tip: sort the keys first (`std::ranges::sort`: `public_key`'s order is BIP 327's KeySort)
 * where the protocol does, so that every signer computes the same key.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signer_keys The signers' keys, at least one.
 * @param pointer_space At least `workspace_size(signer_keys.size())` bytes; zero when the
 * function returns, whatever it returns.
 * @return The aggregate key; `invalid_input_size` for no keys or a short workspace;
 * `backend_failure`.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<aggregate_key> key_aggregate(
    std::span<public_key const> signer_keys, workspace pointer_space) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace on every return, a refusal's included.
    webcpp::crypto::detail::secp256k1_workspace pointer_carver(pointer_space);
    // libsecp256k1 checks the count with ARG_CHECK, whose callback aborts: refused first here.
    if (signer_keys.empty() || pointer_space.size() < workspace_size(signer_keys.size())) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto* const key_pointers = pointer_carver.take<secp256k1_pubkey const*>(signer_keys.size());
    if (key_pointers == nullptr) {
        return error::invalid_input_size;
    }
    for (std::size_t key_index = 0; key_index < signer_keys.size(); ++key_index) {
        key_pointers[key_index] = &access::point(signer_keys[key_index]);
    }
    auto aggregated_key = access::make_opaque<aggregate_key>();
    if (secp256k1_musig_pubkey_agg(secp256k1_context_static, nullptr,
                                   &access::native(aggregated_key), key_pointers,
                                   signer_keys.size()) == 0) {
        return error::backend_failure;
    }
    return aggregated_key;
}

/**
 * A fresh nonce for one signature (`secp256k1_musig_nonce_gen`), its 32 bytes of session
 * randomness drawn inside from crypto's random device, with the key pair's secret, its public
 * key and the aggregate key.
 *
 * Tip: make the nonce when the signature is to be made, and keep it nowhere else: a nonce
 * survives no restart of the program, which is what keeps it from being used twice.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @param signer_pair The signer's key pair, whose context makes the nonce.
 * @param signers_key The aggregate key, with its tweaks.
 * @param message_hash The 32-byte message, when it is known already, or empty.
 * @param extra_input 32 bytes more to mix in, or empty.
 * @return The pair; `invalid_state` moved from; `invalid_input_size` for a message or an
 * extra input that is neither empty nor 32 bytes; `entropy_unavailable`; `backend_failure`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<nonce_pair> nonce_gen(
    basic_keypair<Backend> const& signer_pair, aggregate_key const& signers_key,
    std::span<std::uint8_t const> message_hash = {},
    std::span<std::uint8_t const> extra_input = {}) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    if (!access::keyed(signer_pair)) {
        return error::invalid_state;
    }
    if ((!message_hash.empty() && message_hash.size() != 32) ||
        (!extra_input.empty() && extra_input.size() != 32)) {
        return error::invalid_input_size;
    }
    // libsecp256k1 zeroes the randomness itself once it is used; the secret wipes it again.
    webcpp::crypto::detail::secp256k1_secret session_randomness;
    auto const entropy_drawn =
        random_device().fill(session_randomness.bytes);  // lint-world: the nonce's randomness
    if (!entropy_drawn) {
        return webcpp::crypto::detail::secp256k1_seed_error(entropy_drawn.error());
    }
    webcpp::crypto::detail::secp256k1_secret secret_bytes;
    secp256k1_keypair_sec(access::context(signer_pair), secret_bytes.bytes.data(),
                          &access::pair(signer_pair));
    secp256k1_pubkey const signer_point = webcpp::crypto::detail::secp256k1_public_point(
        access::context(signer_pair), access::pair(signer_pair));
    auto made_secret = access::make_opaque<secret_nonce>();
    auto made_public = access::make_opaque<public_nonce>();
    auto& nonce_state = access::native(made_secret);
    if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_musig_nonce_gen(
            access::context(signer_pair), &nonce_state.nonce_value, &access::native(made_public),
            session_randomness.bytes.data(), secret_bytes.bytes.data(), &signer_point,
            message_hash.empty() ? nullptr : message_hash.data(), &access::native(signers_key),
            extra_input.empty() ? nullptr : extra_input.data()))) {
        return error::backend_failure;
    }
    std::size_t written_size = nonce_state.signer_key.size();
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, nonce_state.signer_key.data(),
                                  &written_size, &signer_point,
                                  webcpp::crypto::detail::secp256k1_compressed);
    nonce_state.fresh = true;
    return nonce_pair{.secret_part = std::move(made_secret), .public_part = made_public};
}

/**
 * Sums the signers' public nonces (`secp256k1_musig_nonce_agg`), as one of them or a
 * coordinator does once every public nonce is in.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signer_nonces Every signer's public nonce, at least one.
 * @param pointer_space At least `workspace_size(signer_nonces.size())` bytes; zero when the
 * function returns, whatever it returns.
 * @return The aggregate nonce; `invalid_input_size` for no nonces or a short workspace;
 * `backend_failure`.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<aggregate_nonce> nonce_aggregate(
    std::span<public_nonce const> signer_nonces, workspace pointer_space) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace on every return, a refusal's included.
    webcpp::crypto::detail::secp256k1_workspace pointer_carver(pointer_space);
    // libsecp256k1 checks the count with ARG_CHECK, whose callback aborts: refused first here.
    if (signer_nonces.empty() || pointer_space.size() < workspace_size(signer_nonces.size())) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto* const nonce_pointers =
        pointer_carver.take<secp256k1_musig_pubnonce const*>(signer_nonces.size());
    if (nonce_pointers == nullptr) {
        return error::invalid_input_size;
    }
    for (std::size_t nonce_index = 0; nonce_index < signer_nonces.size(); ++nonce_index) {
        nonce_pointers[nonce_index] = &access::native(signer_nonces[nonce_index]);
    }
    auto nonce_sum = access::make_opaque<aggregate_nonce>();
    if (secp256k1_musig_nonce_agg(secp256k1_context_static, &access::native(nonce_sum),
                                  nonce_pointers, signer_nonces.size()) == 0) {
        return error::backend_failure;
    }
    return nonce_sum;
}

/**
 * The session of one message (`secp256k1_musig_nonce_process`): the final nonce and the
 * challenge every signer signs.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param nonce_sum The aggregate nonce.
 * @param message_bytes The 32-byte message, as libsecp256k1 signs.
 * @param signers_key The aggregate key, with its tweaks.
 * @return The session; `backend_failure`.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<session> nonce_process(
    aggregate_nonce const& nonce_sum, std::span<std::uint8_t const, 32> message_bytes,
    aggregate_key const& signers_key) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto signing_session = access::make_opaque<session>();
    if (secp256k1_musig_nonce_process(secp256k1_context_static, &access::native(signing_session),
                                      &access::native(nonce_sum), message_bytes.data(),
                                      &access::native(signers_key)) == 0) {
        return error::backend_failure;
    }
    return signing_session;
}

/**
 * This signer's partial signature (`secp256k1_musig_partial_sign`), consuming the nonce: it is
 * taken by value, wiped by the call and destroyed at its end.
 *
 * @tparam Backend The key pair's backend, `backends::secp256k1`.
 * @param signer_pair The signer's key pair.
 * @param signer_nonce The nonce `nonce_gen` made for this key pair, moved in.
 * @param signers_key The aggregate key, with its tweaks.
 * @param signing_session The session of the message.
 * @return The partial signature; `invalid_state` for a moved-from key pair or nonce, a nonce
 * already used, or a nonce made for another key pair; `backend_failure`.
 */
template <class Backend>
[[nodiscard]] boost::system::result<partial_signature> partial_sign(
    basic_keypair<Backend> const& signer_pair, secret_nonce signer_nonce,
    aggregate_key const& signers_key, session const& signing_session) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    using access = webcpp::crypto::detail::secp256k1_access;
    auto& nonce_state = access::native(signer_nonce);
    // libsecp256k1 checks a used nonce and the signer's key with ARG_CHECK, whose callback
    // aborts: refused first here.
    if (!access::keyed(signer_pair) || !nonce_state.fresh) {
        return error::invalid_state;
    }
    secp256k1_pubkey const signer_point = webcpp::crypto::detail::secp256k1_public_point(
        access::context(signer_pair), access::pair(signer_pair));
    std::array<std::uint8_t, 33> signer_key{};
    std::size_t written_size = signer_key.size();
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, signer_key.data(), &written_size,
                                  &signer_point, webcpp::crypto::detail::secp256k1_compressed);
    if (signer_key != nonce_state.signer_key) {
        return error::invalid_state;
    }
    nonce_state.fresh = false;
    auto signature_part = access::make_opaque<partial_signature>();
    if (!webcpp::crypto::detail::secp256k1_accepted(secp256k1_musig_partial_sign(
            access::context(signer_pair), &access::native(signature_part), &nonce_state.nonce_value,
            &access::pair(signer_pair), &access::native(signers_key),
            &access::native(signing_session)))) {
        return error::backend_failure;
    }
    return signature_part;
}

/**
 * Verifies one signer's partial signature (`secp256k1_musig_partial_sig_verify`), which tells
 * a dishonest or faulty signer apart before the signature is aggregated.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signature_part The signer's partial signature.
 * @param signer_nonce The signer's public nonce.
 * @param signer_key The signer's public key.
 * @param signers_key The aggregate key, with its tweaks.
 * @param signing_session The session of the message.
 * @return Nothing; `invalid_signature` when it does not verify.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<void> partial_signature_verify(
    partial_signature const& signature_part, public_nonce const& signer_nonce,
    public_key const& signer_key, aggregate_key const& signers_key,
    session const& signing_session) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    if (secp256k1_musig_partial_sig_verify(
            secp256k1_context_static, &access::native(signature_part),
            &access::native(signer_nonce), &access::point(signer_key), &access::native(signers_key),
            &access::native(signing_session)) == 0) {
        return error::invalid_signature;
    }
    return {};
}

/**
 * The BIP 340 signature of the partial signatures (`secp256k1_musig_partial_sig_agg`), which
 * `crypto::verify(crypto::schnorr, signature, message, key)` checks under
 * `aggregate_key::xonly_public_key()`.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param signing_session The session of the message.
 * @param signature_parts Every signer's partial signature, at least one.
 * @param pointer_space At least `workspace_size(signature_parts.size())` bytes; zero when the
 * function returns, whatever it returns.
 * @return The BIP 340 signature, a `curves::secp256k1::schnorr_signature`; `invalid_input_size`
 * for no partial signatures or a short workspace; `backend_failure`.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<schnorr_signature> partial_signature_aggregate(
    session const& signing_session, std::span<partial_signature const> signature_parts,
    workspace pointer_space) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    // The carver first: it wipes the workspace on every return, a refusal's included.
    webcpp::crypto::detail::secp256k1_workspace pointer_carver(pointer_space);
    // libsecp256k1 checks the count with ARG_CHECK, whose callback aborts: refused first here.
    if (signature_parts.empty() || pointer_space.size() < workspace_size(signature_parts.size())) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto* const part_pointers =
        pointer_carver.take<secp256k1_musig_partial_sig const*>(signature_parts.size());
    if (part_pointers == nullptr) {
        return error::invalid_input_size;
    }
    for (std::size_t part_index = 0; part_index < signature_parts.size(); ++part_index) {
        part_pointers[part_index] = &access::native(signature_parts[part_index]);
    }
    std::array<std::uint8_t, 64> output_bytes{};
    if (secp256k1_musig_partial_sig_agg(secp256k1_context_static, output_bytes.data(),
                                        &access::native(signing_session), part_pointers,
                                        signature_parts.size()) == 0) {
        return error::backend_failure;
    }
    return webcpp::crypto::detail::signature_access::of<schnorr_signature>(output_bytes);
}

/**
 * Parses a signer's public nonce (`secp256k1_musig_pubnonce_parse`): two compressed points.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param encoded_nonce The 66 bytes.
 * @return The nonce; `invalid_input_size` for another length; `invalid_point` for a half that
 * is not a point.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<public_nonce> parse_public_nonce(
    std::span<std::uint8_t const> encoded_nonce) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    if (encoded_nonce.size() != public_nonce_size) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto parsed_nonce = access::make_opaque<public_nonce>();
    if (secp256k1_musig_pubnonce_parse(secp256k1_context_static, &access::native(parsed_nonce),
                                       encoded_nonce.data()) == 0) {
        return error::invalid_point;
    }
    return parsed_nonce;
}

/**
 * Serialises a signer's public nonce (`secp256k1_musig_pubnonce_serialize`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_nonce The nonce.
 * @return The 66 bytes, two compressed points.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] std::array<std::uint8_t, public_nonce_size> serialize_public_nonce(
    public_nonce const& parsed_nonce) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::array<std::uint8_t, public_nonce_size> output_bytes{};
    // A parsed or made nonce always serialises: libsecp256k1 returns 1.
    static_cast<void>(secp256k1_musig_pubnonce_serialize(
        secp256k1_context_static, output_bytes.data(),
        &webcpp::crypto::detail::secp256k1_access::native(parsed_nonce)));
    return output_bytes;
}

/**
 * Parses an aggregate nonce (`secp256k1_musig_aggnonce_parse`): two compressed points, either
 * of which may be the point at infinity, written as 33 zero bytes.
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param encoded_nonce The 66 bytes.
 * @return The nonce; `invalid_input_size` for another length; `invalid_point` for a half that
 * is neither a point nor 33 zero bytes.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<aggregate_nonce> parse_aggregate_nonce(
    std::span<std::uint8_t const> encoded_nonce) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    if (encoded_nonce.size() != aggregate_nonce_size) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto parsed_nonce = access::make_opaque<aggregate_nonce>();
    if (secp256k1_musig_aggnonce_parse(secp256k1_context_static, &access::native(parsed_nonce),
                                       encoded_nonce.data()) == 0) {
        return error::invalid_point;
    }
    return parsed_nonce;
}

/**
 * Serialises an aggregate nonce (`secp256k1_musig_aggnonce_serialize`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_nonce The nonce.
 * @return The 66 bytes, a point at infinity as 33 zero bytes.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] std::array<std::uint8_t, aggregate_nonce_size> serialize_aggregate_nonce(
    aggregate_nonce const& parsed_nonce) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::array<std::uint8_t, aggregate_nonce_size> output_bytes{};
    // A parsed or summed nonce always serialises: libsecp256k1 returns 1.
    static_cast<void>(secp256k1_musig_aggnonce_serialize(
        secp256k1_context_static, output_bytes.data(),
        &webcpp::crypto::detail::secp256k1_access::native(parsed_nonce)));
    return output_bytes;
}

/**
 * Parses a partial signature (`secp256k1_musig_partial_sig_parse`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param encoded_signature The 32 bytes.
 * @return The partial signature; `invalid_input_size` for another length; `invalid_signature`
 * for a scalar not below the group order.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] boost::system::result<partial_signature> parse_partial_signature(
    std::span<std::uint8_t const> encoded_signature) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    if (encoded_signature.size() != partial_signature_size) {
        return error::invalid_input_size;
    }
    secp256k1_selftest();
    using access = webcpp::crypto::detail::secp256k1_access;
    auto parsed_signature = access::make_opaque<partial_signature>();
    if (secp256k1_musig_partial_sig_parse(secp256k1_context_static,
                                          &access::native(parsed_signature),
                                          encoded_signature.data()) == 0) {
        return error::invalid_signature;
    }
    return parsed_signature;
}

/**
 * Serialises a partial signature (`secp256k1_musig_partial_sig_serialize`).
 *
 * @tparam Backend The backend, `backends::secp256k1`.
 * @param parsed_signature The partial signature.
 * @return The 32 bytes.
 */
template <class Backend = default_backend_t<families::secp256k1_musig>>
[[nodiscard]] std::array<std::uint8_t, partial_signature_size> serialize_partial_signature(
    partial_signature const& parsed_signature) noexcept {
    detail::timing_guard const timing_scope;
    static_assert(
        webcpp::crypto::detail::secp256k1_refuses_others<families::secp256k1_musig, Backend>);
    webcpp::crypto::detail::read_canary(WEBCPP_CRYPTO_DETAIL_SECP256K1_CANARY);
    secp256k1_selftest();
    std::array<std::uint8_t, partial_signature_size> output_bytes{};
    // A parsed or made partial signature always serialises: libsecp256k1 returns 1.
    static_cast<void>(secp256k1_musig_partial_sig_serialize(
        secp256k1_context_static, output_bytes.data(),
        &webcpp::crypto::detail::secp256k1_access::native(parsed_signature)));
    return output_bytes;
}

}  // namespace webcpp::crypto::curves::secp256k1::musig

#endif  // WEBCPP_CRYPTO_CURVES_SECP256K1_MUSIG_HPP
