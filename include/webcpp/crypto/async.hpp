// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The asynchronous family (design D23), webcpp::hash's `<webcpp/hash/async.hpp>`'s twin: each
 function an Asio asynchronous operation in webcpp::asio's model, initiated through
 `async_initiate`, so that one call works with a callback, `use_awaitable`, Cobalt's `use_op`,
 `deferred`, `as_tuple`, `use_future` and every other completion token. An operation that returns
 a value completes with `void(boost::system::error_code, T)`, the value second, and on an error
 the empty object a move leaves (a `secret<N>`, a signature or an array of zeros, a `gcm` or a key
 pair without a key, whose every member refuses with `invalid_state`); one without a value completes
 with `void(boost::system::error_code)`.

 - The cheap functions exist on every target, for the algorithms the browser's WebCrypto has.
   Each takes the executor its completion is posted to first. On a synchronous backend, their
   default, they run the synchronous call when the operation is initiated (its guards and its
   work, on the thread that initiates it: the caller's for a callback or `use_awaitable`, the one
   that launches the operation for `deferred`) and complete through a post to that executor,
   whence the completion reaches the handler's associated executor, never inside the initiating
   call.
   - AES-GCM: `async_from_key`, `async_seal` and `async_open`, over `ciphers::gcm`. The other AEADs
     (ChaCha20-Poly1305 and its forms, the secret boxes) are not in WebCrypto: call their `seal`.
   - Ed25519: `async_from_secret` (a key pair from its seed), `async_generate`,
     `async_sign(executor, key_pair, crypto::eddsa, message, token)` and
     `async_verify(executor, crypto::eddsa, signature, message, public_key[, policy], token)`,
     over `curves::ed25519::basic_keypair::sign` and `crypto::verify`, with their inputs: the
     message itself, never a digest, the typed `curves::ed25519::signature` and the typed
     `curves::ed25519::public_key`. Under `crypto::eddsa_prehashed` (Ed25519ph), the same
     functions take `crypto::prehashed{digest}`, the message's SHA-512, on a native backend
     alone: WebCrypto has no Ed25519ph, and the browser's backend stops the build. A key pair of
     an algorithm WebCrypto lacks (secp256k1) is not here: call its own `sign`.
   - X25519: `async_agree`, over `curves::x25519::agree`.
   - P-256: `async_from_secret` (a key pair from its secret scalar), `async_generate`,
     `async_sign(executor, key_pair, crypto::ecdsa_sha256, input, token)` and
     `async_verify(executor, crypto::ecdsa_sha256, signature, input, public_key, token)`, ECDSA
     over `curves::p256::basic_keypair::sign` and `crypto::verify`, with their inputs: the typed
     `curves::p256::ecdsa_signature`, and the message, hashed with SHA-256, as WebCrypto's ECDSA
     with SHA-256 hashes it, or
     `crypto::prehashed{digest}` (which the browser's backend, with no prehash mode, will refuse
     at compile time); and `async_agree`, ECDH's raw x coordinate (WebCrypto's `deriveBits`), over
     `curves::p256::basic_keypair::agree`.
 - The heavy functions (design D32's list) take the work executor first (a
   `webcpp::asio::thread_pool`'s): they check their guards on the caller's thread, run the work on
   the work executor and complete on the handler's associated executor, with webcpp::hash's
   cancellation rules (`detail/heavy.hpp`). They exist only where the build has threads
   (`WEBCPP_CRYPTO_HAS_THREADS`); elsewhere each name refuses at compile time.

 Each cheap function has its member form (design D9):
 `K::async_from_secret(executor, secret_bytes, token)`,
 `C::async_from_key(executor, key_bytes, token)`, `K::async_generate(executor, token)`,
 `key_pair.async_sign(executor, scheme, input, token)`,
 `key_pair.async_agree(executor, peer, token)` (P-256),
 `public_key.async_verify(executor, scheme, signature, input[, policy], token)` and AES-GCM's
 `aead.async_seal` and `aead.async_open`. The classes declare them and this header defines them,
 so that a curve's or a cipher's header never includes Asio; the free function calls the member,
 which runs the synchronous member, so that the four forms of an operation share their guards,
 refusals and errors. X25519's `async_agree` has no member: X25519 has no key pair class.

 The default backend of each is the synchronous function's, `default_async_backend_t<Family>`,
 `default_backend_t<Family>` on every target, Emscripten included: the browser's backend is used
 only where a type names it, so that one program gives the same bytes on every target.

 What a call reads (the object and the bytes its inputs view) is the caller's until the
 completion: a synchronous backend reads it before the call returns, the browser's later.

 The header needs webcpp::asio, `<library>/webcpp/asio//asio` in the program's Jamfile, which
 `<webcpp/crypto.hpp>` does not bring: include it by itself.

 @code
 // exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//gcm-default /webcpp/asio//asio ;
 namespace asio = webcpp::asio;
 namespace crypto = webcpp::crypto;
 using gcm = crypto::ciphers::gcm<crypto::ciphers::aes256<>>;

 // A coroutine makes a key and seals in place on the default backend; each completion, the error
 // code and the value, is posted to the coroutine's executor.
 asio::awaitable<void> seal_message(std::span<std::uint8_t const> key,
                                    std::span<std::uint8_t const> iv,
                                    std::span<std::uint8_t const> additional_data,
                                    std::span<std::uint8_t> data) {
     auto const executor = co_await asio::this_coro::executor;
     auto [made_code, aead] =
         co_await crypto::async_from_key<gcm>(executor, key, asio::as_tuple(asio::use_awaitable));
     if (made_code) { co_return; }
     auto [code, tag] = co_await crypto::async_seal(executor, aead, iv, additional_data, data,
                                                    asio::as_tuple(asio::use_awaitable));
     // `data` holds the ciphertext and `tag` the tag when `code` is clear.
 }
 @endcode

 @see "Asynchronous calls", in the guide.
*/
#ifndef WEBCPP_CRYPTO_ASYNC_HPP
#define WEBCPP_CRYPTO_ASYNC_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/heavy.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/post.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <span>
#include <type_traits>
#include <utility>

namespace webcpp::crypto {

namespace detail {

/**
 * The operations of a backend that completes by itself: part B specialises it for
 * `backends::browser`. Declared only: no synchronous backend reaches it.
 *
 * Each asynchronous function whose backend satisfies @ref asynchronous_backend_v calls one static
 * member function of the specialisation and returns its result, the completion token's
 * `async_result`. The shape is the same for every one: the executor the completion is posted to
 * first, the function's other arguments as the public function takes them, the completion token
 * last, forwarded (`std::forward<CompletionToken>(token)`); the function's explicit template
 * arguments, other than the backend, go to a member template of the same name:
 * - `from_secret<Keypair>(executor, secret_bytes, token)`: a key pair from its secret bytes;
 * - `from_key<Cipher>(executor, key_bytes, token)`: AES-GCM from its key;
 * - `generate<Keypair>(executor, token)`;
 * - `seal(executor, aead, iv_bytes, additional_data_bytes, data_bytes, token)` and
 *   `open(executor, aead, iv_bytes, additional_data_bytes, data_bytes, tag_bytes, token)`;
 * - `sign(executor, key_pair, scheme, input, token)`: the scheme tag (`eddsa_t` for Ed25519,
 *   `ecdsa_sha256_t` for P-256) and the message itself, as `std::span<std::uint8_t const>`,
 *   which for P-256 the engine hashes with SHA-256, as WebCrypto's ECDSA does (a marker never
 *   reaches it: `can_sign` refuses one on a backend that completes by itself);
 * - `verify(executor, scheme, signature, input, public_key, policy, token)` for Ed25519, its
 *   signature `curves::ed25519::signature`, its message span, its key
 *   `curves::ed25519::public_key`, by value, and its policy `curves::ed25519::strict_t`, and
 *   `verify(executor, scheme, signature, input, public_key, token)` for P-256, its signature
 *   `curves::p256::ecdsa_signature`, by value, its key P-256's `basic_public_key` and the message
 *   itself, as `std::span<std::uint8_t const>`, which the engine hashes with SHA-256;
 * - `agree(executor, secret_key, peer_public_key, token)` for X25519, and
 *   `agree(executor, key_pair, peer_public_key, token)` for P-256, its key pair and its peer's
 *   key P-256's types.
 * A signature's input reaches the engine as a view, by value (`detail::kept_input`), never as a
 * reference to the caller's argument, which may be a temporary that a `deferred` operation
 * outlives; the engine keeps by reference only the objects the public function takes by reference
 * (a key pair, a public key, an AEAD), which, with the bytes the views hold, are the caller's
 * until the completion, as the public functions say.
 * The signatures of the completions are the public functions'. The function's guard
 * (`detail::timing_guard`) is held by the public function (the member, and the free function that
 * calls it) before it calls the engine.
 *
 * @tparam Backend `backends::browser`.
 */
template <class Backend>
struct async_engine;

/**
 * The initiation of a cheap function on a synchronous backend: runs the synchronous call (its
 * guards first) when the operation is initiated and posts the completion, its result split by @ref
 * completion_of, to `completion_executor`, whence it reaches the handler's associated executor; the
 * post's storage is the handler's associated allocator's.
 */
struct post_initiation {
    /**
     * Runs `bound_call` and posts `completion_handler` with its error code and, for a call that
     * returns a value, the value, or on an error the empty one (ruling R-A3).
     *
     * @param completion_handler The completion handler.
     * @param completion_executor The executor the completion is posted to.
     * @param bound_call The synchronous call, bound to its arguments.
     */
    template <class Handler, class Executor, class Operation>
    void operator()(Handler&& completion_handler, Executor const& completion_executor,
                    Operation bound_call) const {
        deliver(std::forward<Handler>(completion_handler), completion_executor, bound_call());
    }

private:
    // A call without a value completes with its error code alone.
    template <class Handler, class Executor>
    static void deliver(Handler&& completion_handler, Executor const& completion_executor,
                        boost::system::result<void> const& call_result) {
        boost::system::error_code const completion_code =
            call_result ? boost::system::error_code{} : call_result.error();
        webcpp::asio::post(
            completion_executor,
            webcpp::asio::append(std::forward<Handler>(completion_handler), completion_code));
    }

    // A call with a value completes with it, or on an error with the empty one.
    template <class Handler, class Executor, class Value>
        requires(!std::is_void_v<Value>)
    static void deliver(Handler&& completion_handler, Executor const& completion_executor,
                        boost::system::result<Value>&& call_result) {
        if (call_result) {
            webcpp::asio::post(
                completion_executor,
                webcpp::asio::append(std::forward<Handler>(completion_handler),
                                     boost::system::error_code{}, *std::move(call_result)));
        } else {
            webcpp::asio::post(
                completion_executor,
                webcpp::asio::append(std::forward<Handler>(completion_handler), call_result.error(),
                                     async_access::empty<Value>()));
        }
    }
};

/**
 * Initiates a cheap function on a synchronous backend (design D23): runs `bound_call()` when the
 * operation is initiated (on the initiating thread; for `deferred`, when the deferred operation
 * is launched), and completes through a post to `completion_executor`, never inside the call,
 * with `bound_call()`'s result split into its error code and its value.
 *
 * @tparam CompletionToken Any completion token, of signature `completion_of<R>::type`, `R`
 * `bound_call()`'s result.
 * @param completion_executor The executor the completion is posted to, whence it reaches the
 * handler's associated executor.
 * @param completion_token The completion token.
 * @param bound_call The synchronous call, bound to its arguments: a `noexcept` call without
 * arguments returning `boost::system::result<T>` or `boost::system::result<void>`, called once.
 * @return What the completion token's `async_result` gives.
 */
template <class CompletionToken, class Executor, class Operation>
auto complete_by_post(Executor const& completion_executor, CompletionToken& completion_token,
                      Operation bound_call) {
    static_assert(std::is_nothrow_invocable_v<Operation&>,
                  "webcpp::crypto: an asynchronous operation's call reports its errors as values");
    using signature = completion_of<std::invoke_result_t<Operation&>>::type;
    return webcpp::asio_backend::async_initiate<CompletionToken, signature>(
        post_initiation{}, completion_token, completion_executor, std::move(bound_call));
}

/** Whether `Type` is an AES-GCM, `ciphers::gcm<Cipher>`. */
template <class Type>
inline constexpr bool is_gcm_v = false;

template <class Cipher>
inline constexpr bool is_gcm_v<ciphers::gcm<Cipher>> = true;

/** Whether `Type` is an Ed25519 key pair, `curves::ed25519::basic_keypair<Backend>`. */
template <class Type>
inline constexpr bool is_ed25519_keypair_v = false;

template <class Backend>
inline constexpr bool is_ed25519_keypair_v<curves::ed25519::basic_keypair<Backend>> = true;

/** Whether `Type` is a P-256 key pair, `curves::p256::basic_keypair<Backend>`. */
template <class Type>
inline constexpr bool is_p256_keypair_v = false;

template <class Backend>
inline constexpr bool is_p256_keypair_v<curves::p256::basic_keypair<Backend>> = true;

/** Whether `Type` is a key pair of an algorithm WebCrypto has: Ed25519's or P-256's. */
template <class Type>
inline constexpr bool is_webcrypto_keypair_v =
    is_ed25519_keypair_v<Type> || is_p256_keypair_v<Type>;

/** Whether `Type` is a P-256 public key, `curves::p256::basic_public_key<Backend>`. */
template <class Type>
inline constexpr bool is_p256_public_key_v = false;

template <class Backend>
inline constexpr bool is_p256_public_key_v<curves::p256::basic_public_key<Backend>> = true;

/**
 * Whether an `async_verify` of `Scheme` against the public key `Key` exists: `eddsa_t` and
 * `eddsa_prehashed_t` against an Ed25519 public key, `ecdsa_sha256_t` against a P-256 public key;
 * the catch-all `async_verify` steps aside where it is true.
 *
 * @tparam Scheme A scheme tag.
 * @tparam Key The public key's type, without its reference and qualifiers.
 */
template <class Scheme, class Key>
inline constexpr bool has_async_verifier_v =
    ((std::is_same_v<Scheme, eddsa_t> || std::is_same_v<Scheme, eddsa_prehashed_t>) &&
     std::is_same_v<Key, curves::ed25519::public_key>) ||
    (std::is_same_v<Scheme, ecdsa_sha256_t> && is_p256_public_key_v<Key>);

/**
 * Stops the build with the one reason the key pair `Keypair` does not sign `Input` with `Scheme`:
 * the scheme is not the key pair's, or the input is not one of the scheme's on the key pair's
 * backend (`check_input`'s reasons).
 *
 * @tparam Keypair An Ed25519 or a P-256 key pair's type.
 * @tparam Scheme Any type, a scheme tag or not.
 * @tparam Input The input's type, without its reference and qualifiers.
 */
template <class Keypair, class Scheme, class Input>
constexpr void refuse_async_sign() noexcept {
    if constexpr (!signs_with_v<Keypair, Scheme>) {
        static_assert(refused_v<Scheme>,
                      "webcpp::crypto: async_sign: this key pair does not sign with this scheme: "
                      "an Ed25519 key pair signs with crypto::eddsa or crypto::eddsa_prehashed, a "
                      "P-256 key pair with crypto::ecdsa_sha256.");
    } else {
        check_input<Scheme, Input, typename key_backend<Keypair>::type>();
    }
}

/**
 * Whether `Keypair` is an Ed25519 key pair asked to sign under `eddsa_prehashed` on a backend that
 * completes by itself: what every Ed25519ph function refuses first, WebCrypto having no Ed25519ph.
 *
 * @tparam Keypair Any type.
 * @tparam Scheme Any type.
 */
template <class Keypair, class Scheme>
inline constexpr bool ed25519ph_on_browser_v =
    is_ed25519_keypair_v<Keypair> && std::is_same_v<Scheme, eddsa_prehashed_t> &&
    asynchronous_backend_v<typename key_backend<Keypair>::type>;

/**
 * A valid input as the operation keeps it until it runs: a message as the view of its bytes, a
 * marker as itself, a view too. Neither copies the bytes, which are the caller's until the
 * completion; a temporary that holds the view, such as `prehashed{digest}` made in the call's
 * argument list, does not have to outlive the call, which a `deferred` operation launches later.
 *
 * @tparam Input A message's type or `prehashed<N>`.
 * @param signing_input The message or the marker.
 * @return The view the operation keeps.
 */
template <class Input>
[[nodiscard]] constexpr auto kept_input(Input const& signing_input) noexcept {
    if constexpr (is_prehashed_v<Input>) {
        return signing_input;
    } else {
        return message_bytes(signing_input);
    }
}

/**
 * The initiation of `async_from_secret` once its guard is held, for the free function and the
 * member: the engine of a backend that completes by itself, or `Keypair::from_secret` run when the
 * operation is initiated.
 *
 * @tparam Keypair A key pair of an algorithm WebCrypto has.
 * @param completion_executor The executor the completion is posted to.
 * @param secret_bytes The key pair's secret bytes.
 * @param completion_token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class CompletionToken>
auto initiate_from_secret(Executor const& completion_executor,
                          std::span<std::uint8_t const> secret_bytes,
                          CompletionToken&& completion_token) {
    using backend = Keypair::backend_type;
    if constexpr (asynchronous_backend_v<backend>) {
        return async_engine<backend>::template from_secret<Keypair>(
            completion_executor, secret_bytes, std::forward<CompletionToken>(completion_token));
    } else {
        return complete_by_post(completion_executor, completion_token, [secret_bytes]() noexcept {
            return Keypair::from_secret(secret_bytes);
        });
    }
}

/**
 * The initiation of `async_from_key` once its guard is held, for the free function and the
 * member: the engine of a backend that completes by itself, or `Cipher::from_key` run when the
 * operation is initiated.
 *
 * @tparam Cipher AES-GCM.
 * @param completion_executor The executor the completion is posted to.
 * @param key_bytes The key's bytes.
 * @param completion_token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Cipher, class Executor, class CompletionToken>
auto initiate_from_key(Executor const& completion_executor, std::span<std::uint8_t const> key_bytes,
                       CompletionToken&& completion_token) {
    using backend = Cipher::backend_type;
    if constexpr (asynchronous_backend_v<backend>) {
        return async_engine<backend>::template from_key<Cipher>(
            completion_executor, key_bytes, std::forward<CompletionToken>(completion_token));
    } else {
        return complete_by_post(completion_executor, completion_token,
                                [key_bytes]() noexcept { return Cipher::from_key(key_bytes); });
    }
}

/**
 * The initiation of `async_generate` once its guard is held, for the free function and the
 * member: the engine of a backend that completes by itself, or `Keypair::generate` run when the
 * operation is initiated.
 *
 * @tparam Keypair A key pair of an algorithm WebCrypto has.
 * @param completion_executor The executor the completion is posted to.
 * @param completion_token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class CompletionToken>
auto initiate_generate(Executor const& completion_executor, CompletionToken&& completion_token) {
    using backend = Keypair::backend_type;
    if constexpr (asynchronous_backend_v<backend>) {
        return async_engine<backend>::template generate<Keypair>(
            completion_executor, std::forward<CompletionToken>(completion_token));
    } else {
        return complete_by_post(completion_executor, completion_token,
                                []() noexcept { return Keypair::generate(); });
    }
}

/**
 * The initiation of `async_sign` once its guard is held, for the free function and the member:
 * the key pair, the scheme and the input checked as `crypto::can_sign` checks them, then the
 * engine of a backend that completes by itself, or `key_pair.sign` run when the operation is
 * initiated.
 *
 * @tparam Keypair An Ed25519 or a P-256 key pair.
 * @param completion_executor The executor the completion is posted to.
 * @param key_pair The key pair, the caller's until the completion.
 * @param signing_scheme The scheme.
 * @param signing_input The message or the marker.
 * @param completion_token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class Scheme, class Input, class CompletionToken>
auto initiate_sign(Executor const& completion_executor, Keypair const& key_pair,
                   Scheme signing_scheme, Input const& signing_input,
                   CompletionToken&& completion_token) {
    if constexpr (!can_sign<Keypair, Scheme, Input>) {
        refuse_async_sign<Keypair, Scheme, Input>();
    } else {
        using backend = Keypair::backend_type;
        if constexpr (asynchronous_backend_v<backend>) {
            return async_engine<backend>::sign(completion_executor, key_pair, signing_scheme,
                                               kept_input(signing_input),
                                               std::forward<CompletionToken>(completion_token));
        } else {
            return complete_by_post(
                completion_executor, completion_token,
                [&key_pair, signing_scheme, kept = kept_input(signing_input)]() noexcept {
                    return key_pair.sign(signing_scheme, kept);
                });
        }
    }
}

/**
 * Ed25519's `async_verify` once its guard is held, for the free functions and the members, with
 * and without the policy, under `eddsa` and `eddsa_prehashed`: the scheme, the signature and the
 * input checked as `crypto::can_verify` checks them, then the engine of a backend that completes
 * by itself (`eddsa` alone: the public functions refuse `eddsa_prehashed` there first), or the
 * key's `verify` run when the operation is initiated.
 *
 * @tparam Backend The backend.
 * @tparam Scheme `eddsa_t` or `eddsa_prehashed_t`; another scheme stops the build.
 * @tparam Signature `curves::ed25519::signature`; another type stops the build.
 * @param completion_executor The executor the completion is posted to.
 * @param signature_value The signature, copied into the operation.
 * @param signing_input The message, or under `eddsa_prehashed` the marker of its SHA-512.
 * @param public_key The public key, copied into the operation.
 * @param verification_policy `curves::ed25519::strict`.
 * @param completion_token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Scheme, class Executor, class Signature, class Input,
          class CompletionToken>
auto initiate_verify_ed25519(Executor const& completion_executor, Signature const& signature_value,
                             Input const& signing_input,
                             curves::ed25519::public_key const& public_key,
                             [[maybe_unused]] curves::ed25519::strict_t verification_policy,
                             CompletionToken&& completion_token) {
    if constexpr (!std::is_same_v<Scheme, eddsa_t> && !std::is_same_v<Scheme, eddsa_prehashed_t>) {
        static_assert(refused_v<Scheme>,
                      "webcpp::crypto: an Ed25519 public key verifies crypto::eddsa or "
                      "crypto::eddsa_prehashed.");
    } else if constexpr (std::is_same_v<Scheme, eddsa_prehashed_t> &&
                         asynchronous_backend_v<Backend>) {
        static_assert(
            refused_v<Scheme>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else if constexpr (!check_signature<curves::ed25519::signature, Signature, Scheme>()) {
        // Never compiled into a program: check_signature stopped the build.
    } else if constexpr (!input_valid_v<Scheme, Input, Backend>) {
        check_input<Scheme, Input, Backend>();
    } else if constexpr (asynchronous_backend_v<Backend>) {
        return async_engine<Backend>::verify(
            completion_executor, eddsa, signature_value, kept_input(signing_input), public_key,
            verification_policy, std::forward<CompletionToken>(completion_token));
    } else {
        return complete_by_post(
            completion_executor, completion_token,
            [signature_value, kept = kept_input(signing_input), public_key]() noexcept {
                return public_key.template verify<Backend>(Scheme{}, signature_value, kept,
                                                           curves::ed25519::strict);
            });
    }
}

}  // namespace detail

/**
 * Makes an Ed25519 or a P-256 key pair from its secret bytes, asynchronously:
 * `Keypair::from_secret(secret_bytes)` run when the operation is initiated, its result posted to
 * `completion_executor`.
 *
 * The free form of
 * `Keypair::async_from_secret(completion_executor, secret_bytes, completion_token)`, which it
 * calls.
 *
 * The secret is read before the call returns on a synchronous backend, later on the browser's: it
 * is the caller's until the completion.
 *
 * @tparam Keypair A `curves::ed25519::basic_keypair<Backend>` or a
 * `curves::p256::basic_keypair<Backend>`, on any backend that has it; the other key pairs crypto
 * has are not in WebCrypto: call their `from_secret`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param secret_bytes The seed's `seed_size` bytes for an Ed25519 key pair, the secret scalar's
 * `secret_key_size` (32 bytes, big-endian) for a P-256 key pair.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, Keypair)`; on an error the key pair is empty, and every member
 * refuses with `invalid_state` (`invalid_key_size`, `invalid_secret_key` for a P-256 scalar 0 or
 * not below the group order, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class CompletionToken>
auto async_from_secret(Executor const& completion_executor,
                       std::span<std::uint8_t const> secret_bytes,
                       CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (!detail::is_webcrypto_keypair_v<Keypair>) {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: async_from_secret takes a key pair of an algorithm "
                      "WebCrypto has (Ed25519, P-256): call the synchronous from_secret for the "
                      "others.");
    } else {
        return Keypair::async_from_secret(completion_executor, secret_bytes,
                                          std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Makes an AES-GCM object from its key bytes, asynchronously: `Cipher::from_key(key_bytes)` run
 * when the operation is initiated, its result posted to `completion_executor`.
 *
 * The free form of `Cipher::async_from_key(completion_executor, key_bytes, completion_token)`,
 * which it calls.
 *
 * The key is read before the call returns on a synchronous backend, later on the browser's: it is
 * the caller's until the completion.
 *
 * @tparam Cipher A `ciphers::gcm<BlockCipher>`, on any backend that has it; the other AEADs crypto
 * has are not in WebCrypto: call their `from_key`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param key_bytes `Cipher::key_size` bytes.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, Cipher)`; on an error the object is empty, and every member
 * refuses with `invalid_state` (`invalid_key_size`, `errc::not_enough_memory`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Cipher, class Executor, class CompletionToken>
auto async_from_key(Executor const& completion_executor, std::span<std::uint8_t const> key_bytes,
                    CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (!detail::is_gcm_v<Cipher>) {
        static_assert(detail::refused_v<Cipher>,
                      "webcpp::crypto: async_from_key takes AES-GCM, the AEAD WebCrypto has: call "
                      "from_key for the others.");
    } else {
        return Cipher::async_from_key(completion_executor, key_bytes,
                                      std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Makes an Ed25519 or a P-256 key pair from a fresh seed or scalar, asynchronously:
 * `Keypair::generate()` run when the operation is initiated (the system's generator is drawn from
 * then), its result posted to `completion_executor`.
 *
 * The free form of `Keypair::async_generate(completion_executor, completion_token)`, which it
 * calls.
 *
 * @tparam Keypair A `curves::ed25519::basic_keypair<Backend>`, by default the family's
 * `curves::ed25519::keypair`, or a `curves::p256::basic_keypair<Backend>`; the other key pairs
 * are not in WebCrypto: call their `generate`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, Keypair)`; on an error the key pair is empty, and every member
 * refuses with `invalid_state` (`entropy_unavailable`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair = curves::ed25519::keypair, class Executor, class CompletionToken>
auto async_generate(Executor const& completion_executor, CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (!detail::is_webcrypto_keypair_v<Keypair>) {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: async_generate takes a key pair of an algorithm WebCrypto "
                      "has (Ed25519, P-256): call the synchronous generate for the others.");
    } else {
        return Keypair::async_generate(completion_executor,
                                       std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Seals a message in place, asynchronously: `aead_cipher.seal` run when the operation is initiated,
 * its result posted to `completion_executor`.
 *
 * The free form of the member `aead_cipher.async_seal`, with the same arguments, which it
 * calls.
 *
 * `aead_cipher` and the spans are the caller's until the completion: a synchronous backend reads
 * and writes them before the call returns, the browser's later. `data_bytes` holds the ciphertext
 * at the completion. A guard's refusal (`invalid_iv_size`, `message_too_long`, `invalid_state`)
 * leaves it untouched, a backend's failure zeroes it, as `seal` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `seal`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param aead_cipher The keyed object.
 * @param iv_bytes 1 to `max_iv_size` bytes, never reused under this key.
 * @param additional_data_bytes Authenticated, not encrypted.
 * @param data_bytes The message.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, Gcm::result_type)`: the tag; on an error the zeroed tag.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_seal(Executor const& completion_executor, Gcm& aead_cipher,
                std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (!detail::is_gcm_v<std::remove_cv_t<Gcm>>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_seal takes AES-GCM, the AEAD WebCrypto has: call seal "
                      "for the others.");
    } else {
        return aead_cipher.async_seal(completion_executor, iv_bytes, additional_data_bytes,
                                      data_bytes, std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Opens a message in place, asynchronously: `aead_cipher.open` run when the operation is initiated,
 * its result posted to `completion_executor`.
 *
 * The free form of the member `aead_cipher.async_open`, with the same arguments, which it
 * calls.
 *
 * `aead_cipher` and the spans are the caller's until the completion. `data_bytes` holds the
 * plaintext at a successful completion; a wrong tag (`authentication_failed`) or a backend's
 * failure zeroes it, a guard's refusal leaves it untouched, as `open` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `open`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param aead_cipher The keyed object.
 * @param iv_bytes The IV of the seal.
 * @param additional_data_bytes The additional data of the seal.
 * @param data_bytes The ciphertext.
 * @param tag_bytes The seal's tag, 16 bytes.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_open(Executor const& completion_executor, Gcm& aead_cipher,
                std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes,
                CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (!detail::is_gcm_v<std::remove_cv_t<Gcm>>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_open takes AES-GCM, the AEAD WebCrypto has: call open "
                      "for the others.");
    } else {
        return aead_cipher.async_open(completion_executor, iv_bytes, additional_data_bytes,
                                      data_bytes, tag_bytes,
                                      std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Signs with an Ed25519 or a P-256 key pair, asynchronously:
 * `key_pair.sign(signing_scheme, signing_input)` run when the operation is initiated, its result
 * posted to `completion_executor`.
 *
 * The free form of the member `key_pair.async_sign`, with the same arguments, which it calls.
 *
 * Ed25519 signs the message with `crypto::eddsa`, or with `crypto::eddsa_prehashed` (Ed25519ph)
 * `crypto::prehashed{digest}`, the message's 64-byte SHA-512, on a native backend alone (WebCrypto
 * has no Ed25519ph: the browser's backend stops the build first); P-256 signs with
 * `crypto::ecdsa_sha256` the message, which it hashes with SHA-256, as WebCrypto's ECDSA with
 * SHA-256 signs, or `crypto::prehashed{digest}` (RFC 6979's nonce: the same key and input give the
 * same signature; S low).
 *
 * The key pair, the scheme and the input are checked as `crypto::can_sign` checks them, before
 * anything else: another pair stops the build with its reason, and so does a marker on a backend
 * that completes by itself (WebCrypto has no prehash mode). `key_pair` and the bytes the input
 * views are the caller's until the completion.
 *
 * @tparam Keypair A `curves::ed25519::basic_keypair<Backend>` or a
 * `curves::p256::basic_keypair<Backend>`; the other key pairs are not in WebCrypto: call the key
 * pair's own `sign`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Scheme `crypto::eddsa_t` or `crypto::eddsa_prehashed_t` for Ed25519,
 * `crypto::ecdsa_sha256_t` for P-256.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or for P-256 `crypto::prehashed<32>`; under `crypto::eddsa_prehashed`,
 * `crypto::prehashed<64>` alone.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param key_pair The key pair.
 * @param signing_scheme `crypto::eddsa`, `crypto::eddsa_prehashed` or `crypto::ecdsa_sha256`.
 * @param signing_input The message, or for P-256 `crypto::prehashed{digest}`, its 32-byte SHA-256
 * digest, or under `crypto::eddsa_prehashed` `crypto::prehashed{digest}`, its 64-byte SHA-512
 * digest.
 * @param completion_token The completion token, of signature `void(error_code, signature)`, the
 * signature the key pair's type, `curves::ed25519::signature` or `curves::p256::ecdsa_signature`
 * (r then s, IEEE P1363's form, WebCrypto's); on an error the signature of zeros
 * (`invalid_state`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class Scheme, class Input, class CompletionToken>
auto async_sign(Executor const& completion_executor, Keypair const& key_pair, Scheme signing_scheme,
                Input const& signing_input, CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::ed25519ph_on_browser_v<Keypair, Scheme>) {
        static_assert(
            detail::refused_v<Scheme>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else if constexpr (!detail::is_webcrypto_keypair_v<Keypair>) {
        static_assert(
            detail::refused_v<Keypair>,
            "webcpp::crypto: async_sign takes a key pair of an algorithm WebCrypto has "
            "(Ed25519, P-256): call the key pair's synchronous signing function for the others.");
    } else {
        return key_pair.async_sign(completion_executor, signing_scheme, signing_input,
                                   std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Verifies an Ed25519 signature (RFC 8032's pure Ed25519), asynchronously, strictly:
 * `crypto::verify<Backend>(crypto::eddsa, signature_value, message_bytes, public_key)` run when the
 * operation is initiated, its result posted to `completion_executor`.
 *
 * The free form of the member `public_key.async_verify<Backend>`, with the same arguments,
 * `crypto::eddsa` first, which it calls, and which runs the key's `verify`, with the same work.
 *
 * The signature and the input are checked as `crypto::can_verify` checks them, before anything
 * else: a signature of another type, bytes included, stops the build, and so does a marker
 * (Ed25519 signs the message itself). The message's bytes are the caller's until the completion;
 * the signature and the public key are copied.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Signature `curves::ed25519::signature`; another type stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param signing_scheme `crypto::eddsa`.
 * @param signature_value The signature; bytes from a peer are made into one by
 * `curves::ed25519::signature::from_bytes`.
 * @param message_bytes The signed bytes.
 * @param public_key The signer's public key.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`:
 * `invalid_signature` for a signature that does not verify; `backend_failure`.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor,
          class Signature, class Input, class CompletionToken>
auto async_verify(Executor const& completion_executor, eddsa_t signing_scheme,
                  Signature const& signature_value, Input const& message_bytes,
                  curves::ed25519::public_key const& public_key,
                  CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return public_key.template async_verify<Backend>(
        completion_executor, signing_scheme, signature_value, message_bytes,
        std::forward<CompletionToken>(completion_token));
}

/**
 * Verifies an Ed25519 signature under the verification policy given, asynchronously: as the
 * overload without it, with `crypto::verify`'s policy argument before the token.
 *
 * The policy is a policy tag, never deduced from another argument, so that a completion token is
 * never read as one.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Signature `curves::ed25519::signature`; another type stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param signing_scheme `crypto::eddsa`.
 * @param signature_value The signature.
 * @param message_bytes The signed bytes.
 * @param public_key The signer's public key.
 * @param verification_policy `curves::ed25519::strict` (libsodium's rules), the only policy
 * declared.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`, as
 * the overload without a policy completes.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor,
          class Signature, class Input, class CompletionToken>
auto async_verify(Executor const& completion_executor, eddsa_t signing_scheme,
                  Signature const& signature_value, Input const& message_bytes,
                  curves::ed25519::public_key const& public_key,
                  curves::ed25519::strict_t verification_policy,
                  CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return public_key.template async_verify<Backend>(
        completion_executor, signing_scheme, signature_value, message_bytes, verification_policy,
        std::forward<CompletionToken>(completion_token));
}

/**
 * Verifies an Ed25519ph signature (RFC 8032's Ed25519 over a message's SHA-512), asynchronously,
 * strictly: `crypto::verify<Backend>` of `crypto::eddsa_prehashed` run when the operation is
 * initiated, its result posted to `completion_executor`.
 *
 * The free form of the member `public_key.async_verify<Backend>`, with the same arguments, which
 * it calls, and which runs the key's `verify`, with the same work. It runs on a native backend: on
 * one that completes by itself it stops the build first (WebCrypto has no Ed25519ph).
 *
 * The signature and the input are checked as `crypto::can_verify` checks them, before anything
 * else: a signature of another type, bytes included, stops the build, and so do a message and a
 * digest of another size. The digest's bytes are the caller's until the completion; the signature
 * and the public key are copied.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Signature `curves::ed25519::signature`; another type stops the build.
 * @tparam Input `crypto::prehashed<64>`, the message's SHA-512.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param signing_scheme `crypto::eddsa_prehashed`.
 * @param signature_value The signature; bytes from a peer are made into one by
 * `curves::ed25519::signature::from_bytes`.
 * @param digest_input `crypto::prehashed{digest}`, the 64 bytes of the message's SHA-512.
 * @param public_key The signer's public key.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`:
 * `invalid_signature` for a signature that does not verify, an `eddsa` signature included;
 * `backend_failure`.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor,
          class Signature, class Input, class CompletionToken>
auto async_verify(Executor const& completion_executor, eddsa_prehashed_t signing_scheme,
                  Signature const& signature_value, Input const& digest_input,
                  curves::ed25519::public_key const& public_key,
                  CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        static_assert(
            detail::refused_v<Backend>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else {
        return public_key.template async_verify<Backend>(
            completion_executor, signing_scheme, signature_value, digest_input,
            std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Verifies an Ed25519ph signature under the verification policy given, asynchronously: as the
 * overload without it, with `crypto::verify`'s policy argument before the token.
 *
 * The policy is a policy tag, never deduced from another argument, so that a completion token is
 * never read as one.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Signature `curves::ed25519::signature`; another type stops the build.
 * @tparam Input `crypto::prehashed<64>`, the message's SHA-512.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param signing_scheme `crypto::eddsa_prehashed`.
 * @param signature_value The signature.
 * @param digest_input `crypto::prehashed{digest}`, the 64 bytes of the message's SHA-512.
 * @param public_key The signer's public key.
 * @param verification_policy `curves::ed25519::strict` (libsodium's rules), the only policy
 * declared.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`, as
 * the overload without a policy completes.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor,
          class Signature, class Input, class CompletionToken>
auto async_verify(Executor const& completion_executor, eddsa_prehashed_t signing_scheme,
                  Signature const& signature_value, Input const& digest_input,
                  curves::ed25519::public_key const& public_key,
                  curves::ed25519::strict_t verification_policy,
                  CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        static_assert(
            detail::refused_v<Backend>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else {
        return public_key.template async_verify<Backend>(
            completion_executor, signing_scheme, signature_value, digest_input, verification_policy,
            std::forward<CompletionToken>(completion_token));
    }
}

/**
 * Verifies a P-256 ECDSA signature over SHA-256, asynchronously:
 * `crypto::verify(crypto::ecdsa_sha256, signature_value, signing_input, public_key)` run when the
 * operation is initiated, its result posted to `completion_executor`; the message is hashed with
 * SHA-256, as WebCrypto's ECDSA with SHA-256 verifies, or `crypto::prehashed{digest}` gives its
 * digest.
 *
 * The free form of the member `public_key.async_verify`, with the same arguments,
 * `crypto::ecdsa_sha256` first, which it calls, and which runs the key's `verify`, with the same
 * work.
 *
 * A high S and a low S are both accepted, as `crypto::verify` and WebCrypto accept them. The
 * signature and the input are checked as `crypto::can_verify` checks them, before anything else:
 * a signature of another type, bytes included, stops the build, and so does a marker on a backend
 * that completes by itself. The key and the bytes the input views are the caller's until the
 * completion; the signature is copied.
 *
 * @tparam Backend The key's backend, which verifies: deduced from the key, or named first, as on
 * every curve.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Signature `curves::p256::ecdsa_signature`; another type stops the build.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or `crypto::prehashed<32>`.
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param signing_scheme `crypto::ecdsa_sha256`.
 * @param signature_value The signature, r then s (IEEE P1363's form, WebCrypto's); bytes from a
 * peer are made into one by `curves::p256::ecdsa_signature::from_bytes`, and DER by
 * `curves::p256::from_der`.
 * @param signing_input The signed message, or `crypto::prehashed{digest}`, its 32-byte SHA-256
 * digest.
 * @param public_key The signer's public key, validated when it was made.
 * @param completion_token The completion token, of signature `void(boost::system::error_code)`:
 * `invalid_signature` for an r or an s that is 0 or not below n, and one that does not verify.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Executor, class Signature, class Input, class CompletionToken>
auto async_verify(Executor const& completion_executor, ecdsa_sha256_t signing_scheme,
                  Signature const& signature_value, Input const& signing_input,
                  curves::p256::basic_public_key<Backend> const& public_key,
                  CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return public_key.async_verify(completion_executor, signing_scheme, signature_value,
                                   signing_input, std::forward<CompletionToken>(completion_token));
}

/**
 * Stops the build: no `async_verify` checks a signature of `Scheme` against this public key.
 *
 * The asynchronous family has the algorithms WebCrypto has, and Ed25519ph on a native backend:
 * Ed25519's and P-256's overloads above are chosen for their keys; this one only when neither is,
 * and it names them.
 *
 * @tparam Backend Ignored: the first template parameter, as on every `async_verify`.
 * @tparam Executor The executor's type.
 * @tparam Scheme A scheme tag.
 * @tparam Signature The signature's type.
 * @tparam Input The input's type.
 * @tparam PublicKey The public key's type.
 * @tparam CompletionToken The completion token's type.
 * @param completion_executor The executor.
 * @param signing_scheme The scheme.
 * @param signature_value The signature.
 * @param signing_input The message or the marker.
 * @param public_key The public key.
 * @param completion_token The completion token.
 */
template <class Backend = void, class Executor, class Scheme, class Signature, class Input,
          class PublicKey, class CompletionToken>
    requires(detail::is_scheme_v<Scheme> &&
             !detail::has_async_verifier_v<Scheme, std::remove_cvref_t<PublicKey>>)
void async_verify([[maybe_unused]] Executor const& completion_executor,
                  [[maybe_unused]] Scheme signing_scheme,
                  [[maybe_unused]] Signature const& signature_value,
                  [[maybe_unused]] Input const& signing_input,
                  [[maybe_unused]] PublicKey const& public_key,
                  [[maybe_unused]] CompletionToken&& completion_token) {
    static_assert(detail::refused_v<Scheme>,
                  "webcpp::crypto: async_verify takes crypto::eddsa or crypto::eddsa_prehashed "
                  "with a curves::ed25519::public_key or crypto::ecdsa_sha256 with a "
                  "curves::p256::basic_public_key, the algorithms WebCrypto has: call "
                  "crypto::verify for the others.");
}

/**
 * Agrees an X25519 shared secret, asynchronously: `curves::x25519::agree<Backend>` run when the
 * operation is initiated, its result posted to `completion_executor`.
 *
 * The spans are the caller's until the completion.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param secret_key 32 bytes.
 * @param peer_public_key 32 bytes.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, secret<32>)`: the shared secret; on an error a secret of zeros
 * (`invalid_key_size`, `invalid_public_key`, `weak_public_key`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::x25519>, class Executor,
          class CompletionToken>
auto async_agree(Executor const& completion_executor, std::span<std::uint8_t const> secret_key,
                 std::span<std::uint8_t const> peer_public_key,
                 CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::agree(
            completion_executor, secret_key, peer_public_key,
            std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token, [secret_key, peer_public_key]() noexcept {
                return curves::x25519::agree<Backend>(secret_key, peer_public_key);
            });
    }
}

/**
 * Agrees a P-256 shared secret, ECDH's raw x coordinate, asynchronously:
 * `key_pair.agree(peer_public_key)` run when the operation is initiated, its result posted to
 * `completion_executor`, as WebCrypto's `deriveBits` with ECDH on P-256 gives its 256 bits.
 *
 * The free form of `key_pair.async_agree(completion_executor, peer_public_key, completion_token)`,
 * which it calls.
 *
 * The x coordinate is not a key: a protocol hashes it into its keys (with HKDF, for instance).
 * The key pair and the peer's key are the caller's until the completion.
 *
 * @tparam Backend The backend of the key pair and of the peer's key.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `completion_token` states.
 * @param completion_executor The executor the completion is posted to.
 * @param key_pair This side's key pair.
 * @param peer_public_key The peer's public key, validated when it was made.
 * @param completion_token The completion token, of signature
 * `void(boost::system::error_code, secret<32>)`: the shared x, big-endian; on an error a secret of
 * zeros (`invalid_state` for an empty key pair, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Executor, class CompletionToken>
auto async_agree(Executor const& completion_executor,
                 curves::p256::basic_keypair<Backend> const& key_pair,
                 curves::p256::basic_public_key<Backend> const& peer_public_key,
                 CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return key_pair.async_agree(completion_executor, peer_public_key,
                                std::forward<CompletionToken>(completion_token));
}

// The asynchronous members (design D9), declared in their classes and defined here, so that a
// curve's or a cipher's header never includes Asio. Each holds its own guard and initiates as the
// free function, which calls it, does.

template <class Cipher>
template <class Executor, class CompletionToken>
auto ciphers::gcm<Cipher>::async_from_key(Executor const& completion_executor,
                                          std::span<std::uint8_t const> key_bytes,
                                          CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return detail::initiate_from_key<gcm>(completion_executor, key_bytes,
                                          std::forward<CompletionToken>(completion_token));
}

template <class Cipher>
template <class Executor, class CompletionToken>
auto ciphers::gcm<Cipher>::async_seal(Executor const& completion_executor,
                                      std::span<std::uint8_t const> iv_bytes,
                                      std::span<std::uint8_t const> additional_data_bytes,
                                      std::span<std::uint8_t> data_bytes,
                                      CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<backend>) {
        return detail::async_engine<backend>::seal(completion_executor, *this, iv_bytes,
                                                   additional_data_bytes, data_bytes,
                                                   std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token,
            [this, iv_bytes, additional_data_bytes, data_bytes]() noexcept {
                return seal(iv_bytes, additional_data_bytes, data_bytes);
            });
    }
}

template <class Cipher>
template <class Executor, class CompletionToken>
auto ciphers::gcm<Cipher>::async_open(Executor const& completion_executor,
                                      std::span<std::uint8_t const> iv_bytes,
                                      std::span<std::uint8_t const> additional_data_bytes,
                                      std::span<std::uint8_t> data_bytes,
                                      std::span<std::uint8_t const> tag_bytes,
                                      CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<backend>) {
        return detail::async_engine<backend>::open(completion_executor, *this, iv_bytes,
                                                   additional_data_bytes, data_bytes, tag_bytes,
                                                   std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token,
            [this, iv_bytes, additional_data_bytes, data_bytes, tag_bytes]() noexcept {
                return open(iv_bytes, additional_data_bytes, data_bytes, tag_bytes);
            });
    }
}

template <class Backend>
template <class Executor, class CompletionToken>
auto curves::ed25519::basic_keypair<Backend>::async_from_secret(
    Executor const& completion_executor, std::span<std::uint8_t const> seed_bytes,
    CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return detail::initiate_from_secret<basic_keypair>(
        completion_executor, seed_bytes, std::forward<CompletionToken>(completion_token));
}

template <class Backend>
template <class Executor, class CompletionToken>
auto curves::ed25519::basic_keypair<Backend>::async_generate(Executor const& completion_executor,
                                                             CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return detail::initiate_generate<basic_keypair>(
        completion_executor, std::forward<CompletionToken>(completion_token));
}

template <class Backend>
template <class Executor, class Scheme, class Input, class CompletionToken>
auto curves::ed25519::basic_keypair<Backend>::async_sign(Executor const& completion_executor,
                                                         Scheme signing_scheme,
                                                         Input const& message_input,
                                                         CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    if constexpr (detail::ed25519ph_on_browser_v<basic_keypair, Scheme>) {
        static_assert(
            detail::refused_v<Scheme>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else {
        return detail::initiate_sign(completion_executor, *this, signing_scheme, message_input,
                                     std::forward<CompletionToken>(completion_token));
    }
}

template <class Backend, class Executor, class Scheme, class Signature, class Input,
          class CompletionToken>
auto curves::ed25519::public_key::async_verify(Executor const& completion_executor,
                                               [[maybe_unused]] Scheme signing_scheme,
                                               Signature const& signature_value,
                                               Input const& message_input,
                                               CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    if constexpr (std::is_same_v<Scheme, eddsa_prehashed_t> &&
                  detail::asynchronous_backend_v<Backend>) {
        static_assert(
            detail::refused_v<Scheme>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else {
        return detail::initiate_verify_ed25519<Backend, Scheme>(
            completion_executor, signature_value, message_input, *this, strict,
            std::forward<CompletionToken>(completion_token));
    }
}

template <class Backend, class Executor, class Scheme, class Signature, class Input,
          class CompletionToken>
auto curves::ed25519::public_key::async_verify(Executor const& completion_executor,
                                               [[maybe_unused]] Scheme signing_scheme,
                                               Signature const& signature_value,
                                               Input const& message_input, strict_t verify_policy,
                                               CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    if constexpr (std::is_same_v<Scheme, eddsa_prehashed_t> &&
                  detail::asynchronous_backend_v<Backend>) {
        static_assert(
            detail::refused_v<Scheme>,
            "webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, "
            "async_sign and async_verify run on a native backend.");
    } else {
        return detail::initiate_verify_ed25519<Backend, Scheme>(
            completion_executor, signature_value, message_input, *this, verify_policy,
            std::forward<CompletionToken>(completion_token));
    }
}

template <class Backend>
template <class Executor, class CompletionToken>
auto curves::p256::basic_keypair<Backend>::async_from_secret(
    Executor const& completion_executor, std::span<std::uint8_t const> secret_scalar,
    CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return detail::initiate_from_secret<basic_keypair>(
        completion_executor, secret_scalar, std::forward<CompletionToken>(completion_token));
}

template <class Backend>
template <class Executor, class CompletionToken>
auto curves::p256::basic_keypair<Backend>::async_generate(Executor const& completion_executor,
                                                          CompletionToken&& completion_token) {
    detail::timing_guard const timing_scope;
    return detail::initiate_generate<basic_keypair>(
        completion_executor, std::forward<CompletionToken>(completion_token));
}

template <class Backend>
template <class Executor, class Scheme, class Input, class CompletionToken>
auto curves::p256::basic_keypair<Backend>::async_sign(Executor const& completion_executor,
                                                      Scheme signing_scheme,
                                                      Input const& signing_input,
                                                      CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    return detail::initiate_sign(completion_executor, *this, signing_scheme, signing_input,
                                 std::forward<CompletionToken>(completion_token));
}

template <class Backend>
template <class Executor, class CompletionToken>
auto curves::p256::basic_keypair<Backend>::async_agree(Executor const& completion_executor,
                                                       basic_public_key<Backend> const& peer_key,
                                                       CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::agree(
            completion_executor, *this, peer_key, std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(completion_executor, completion_token,
                                        [this, &peer_key]() noexcept { return agree(peer_key); });
    }
}

template <class Backend>
template <class Executor, class Scheme, class Signature, class Input, class CompletionToken>
auto curves::p256::basic_public_key<Backend>::async_verify(
    Executor const& completion_executor, [[maybe_unused]] Scheme signing_scheme,
    Signature const& signature_value, Input const& signing_input,
    CompletionToken&& completion_token) const {
    detail::timing_guard const timing_scope;
    if constexpr (!std::is_same_v<Scheme, ecdsa_sha256_t>) {
        static_assert(detail::refused_v<Scheme>,
                      "webcpp::crypto: a P-256 public key verifies crypto::ecdsa_sha256.");
    } else if constexpr (!detail::check_signature<ecdsa_signature, Signature, ecdsa_sha256_t>()) {
        // Never compiled into a program: check_signature stopped the build.
    } else if constexpr (!detail::input_valid_v<ecdsa_sha256_t, Input, Backend>) {
        detail::check_input<ecdsa_sha256_t, Input, Backend>();
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::verify(
            completion_executor, ecdsa_sha256, signature_value, detail::kept_input(signing_input),
            *this, std::forward<CompletionToken>(completion_token));
    } else {
        return detail::complete_by_post(
            completion_executor, completion_token,
            [this, signature_value,
             kept = detail::kept_input(signing_input)]() noexcept -> boost::system::result<void> {
                return verify(ecdsa_sha256, signature_value, kept);
            });
    }
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_ASYNC_HPP
