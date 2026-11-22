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
 the empty object a move leaves (a `secret<N>` or an array of zeros, a `gcm` or a key pair without
 a key, whose every member refuses with `invalid_state`); one without a value completes with
 `void(boost::system::error_code)`.

 - The cheap functions exist on every target, for the algorithms the browser's WebCrypto has.
   Each takes the executor its completion is posted to first. On a synchronous backend, their
   default, they run the synchronous call when the operation is initiated (its guards and its
   work, on the thread that initiates it: the caller's for a callback or `use_awaitable`, the one
   that launches the operation for `deferred`) and complete through a post to that executor,
   whence the completion reaches the handler's associated executor, never inside the initiating
   call.
   - AES-GCM: `async_make`, `async_seal` and `async_open`, over `ciphers::gcm`. The other AEADs
     (ChaCha20-Poly1305 and its forms, the secret boxes) are not in WebCrypto: call their `seal`.
   - Ed25519: `async_make` (a key pair from its seed), `async_generate`,
     `async_sign(executor, key_pair, crypto::eddsa, message, token)` and
     `async_verify(executor, crypto::eddsa, signature, message, public_key[, policy], token)`,
     over `curves::ed25519::basic_keypair::sign` and `crypto::verify`, with their inputs: the
     message itself, never a digest, and the 32-byte public key. A key pair of an algorithm
     WebCrypto lacks (secp256k1) is not here: call its own `sign`.
   - X25519: `async_agree`, over `curves::x25519::agree`.
   - P-256: `async_make` (a key pair from its secret scalar), `async_generate`,
     `async_sign(executor, key_pair, crypto::ecdsa_sha256, input, token)` and
     `async_verify(executor, crypto::ecdsa_sha256, signature, input, public_key, token)`, ECDSA
     over `curves::p256::basic_keypair::sign` and `crypto::verify`, with their inputs: the message,
     hashed with SHA-256, as WebCrypto's ECDSA with SHA-256 hashes it, or
     `crypto::prehashed{digest}` (which the browser's backend, with no prehash mode, will refuse
     at compile time); and `async_agree`, ECDH's raw x coordinate (WebCrypto's `deriveBits`), over
     `curves::p256::basic_keypair::ecdh_x`.
 - The heavy functions (design D32's list) take the work executor first (a
   `webcpp::asio::thread_pool`'s): they check their guards on the caller's thread, run the work on
   the work executor and complete on the handler's associated executor, with webcpp::hash's
   cancellation rules (`detail/heavy.hpp`). They exist only where the build has threads
   (`WEBCPP_CRYPTO_HAS_THREADS`); elsewhere each name refuses at compile time.

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
         co_await crypto::async_make<gcm>(executor, key, asio::as_tuple(asio::use_awaitable));
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

/**
 * The backend of the asynchronous family when a call names none (ruling R-A4): the synchronous
 * function's, `default_backend_t<Family>`, on every target, Emscripten included.
 *
 * The browser's backend is never a default: a program names it in the type to reach WebCrypto.
 *
 * @tparam Family A family tag of `families` that has a default.
 */
template <class Family>
using default_async_backend_t = default_backend_t<Family>;

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
 * - `make<Algorithm>(executor, key_bytes, token)`: AES-GCM or a key pair from its bytes;
 * - `generate<Keypair>(executor, token)`;
 * - `seal(executor, aead, iv_bytes, additional_data_bytes, data_bytes, token)` and
 *   `open(executor, aead, iv_bytes, additional_data_bytes, data_bytes, tag_bytes, token)`;
 * - `sign(executor, key_pair, scheme, input, token)`: the scheme tag (`eddsa_t` for Ed25519,
 *   `ecdsa_sha256_t` for P-256) and the message itself, as `std::span<std::uint8_t const>`,
 *   which for P-256 the engine hashes with SHA-256, as WebCrypto's ECDSA does (a marker never
 *   reaches it: `can_sign` refuses one on a backend that completes by itself);
 * - `verify(executor, scheme, signature, input, public_key, policy, token)` for Ed25519, its
 *   signature, its message and its key spans and its policy `curves::ed25519::strict_t`, and
 *   `verify(executor, scheme, signature, input, public_key, token)` for P-256, its key P-256's
 *   `basic_public_key`, the signature a span of any size and the message itself, as
 *   `std::span<std::uint8_t const>`, which the engine hashes with SHA-256;
 * - `agree(executor, secret_key, peer_public_key, token)` for X25519, and
 *   `agree(executor, key_pair, peer_public_key, token)` for P-256, its key pair and its peer's
 *   key P-256's types.
 * A signature's input reaches the engine as a view, by value (`detail::kept_input`), never as a
 * reference to the caller's argument, which may be a temporary that a `deferred` operation
 * outlives; the engine keeps by reference only the objects the public function takes by reference
 * (a key pair, a public key, an AEAD), which, with the bytes the views hold, are the caller's
 * until the completion, as the public functions say.
 * The signatures of the completions are the public functions'. The function's guard
 * (`detail::timing_guard`) is held by the public function before it calls the engine.
 *
 * @tparam Backend `backends::browser`.
 */
template <class Backend>
struct async_engine;

/**
 * The initiation of a cheap function on a synchronous backend: runs the synchronous call (its
 * guards first) when the operation is initiated and posts the completion, its result split by @ref
 * completion_of, to `executor`, whence it reaches the handler's associated executor; the post's
 * storage is the handler's associated allocator's.
 */
struct post_initiation {
    /**
     * Runs `operation` and posts `handler` with its error code and, for a call that returns a
     * value, the value, or on an error the empty one (ruling R-A3).
     *
     * @param handler The completion handler.
     * @param executor The executor the completion is posted to.
     * @param operation The synchronous call, bound to its arguments.
     */
    template <class Handler, class Executor, class Operation>
    void operator()(Handler&& handler, Executor const& executor, Operation operation) const {
        deliver(std::forward<Handler>(handler), executor, operation());
    }

private:
    // A call without a value completes with its error code alone.
    template <class Handler, class Executor>
    static void deliver(Handler&& handler, Executor const& executor,
                        boost::system::result<void> const& done) {
        boost::system::error_code const code = done ? boost::system::error_code{} : done.error();
        webcpp::asio::post(executor, webcpp::asio::append(std::forward<Handler>(handler), code));
    }

    // A call with a value completes with it, or on an error with the empty one.
    template <class Handler, class Executor, class Value>
        requires(!std::is_void_v<Value>)
    static void deliver(Handler&& handler, Executor const& executor,
                        boost::system::result<Value>&& done) {
        if (done) {
            webcpp::asio::post(executor,
                               webcpp::asio::append(std::forward<Handler>(handler),
                                                    boost::system::error_code{}, *std::move(done)));
        } else {
            webcpp::asio::post(executor,
                               webcpp::asio::append(std::forward<Handler>(handler), done.error(),
                                                    async_access::empty<Value>()));
        }
    }
};

/**
 * Initiates a cheap function on a synchronous backend (design D23): runs `operation()` when the
 * operation is initiated (on the initiating thread; for `deferred`, when the deferred operation
 * is launched), and completes through a post to `executor`, never inside the call,
 * with `operation()`'s result split into its error code and its value.
 *
 * @tparam CompletionToken Any completion token, of signature `completion_of<R>::type`, `R`
 * `operation()`'s result.
 * @param executor The executor the completion is posted to, whence it reaches the handler's
 * associated executor.
 * @param token The completion token.
 * @param operation The synchronous call, bound to its arguments: a `noexcept` call without
 * arguments returning `boost::system::result<T>` or `boost::system::result<void>`, called once.
 * @return What the completion token's `async_result` gives.
 */
template <class CompletionToken, class Executor, class Operation>
auto complete_by_post(Executor const& executor, CompletionToken& token, Operation operation) {
    static_assert(std::is_nothrow_invocable_v<Operation&>,
                  "webcpp::crypto: an asynchronous operation's call reports its errors as values");
    using signature = completion_of<std::invoke_result_t<Operation&>>::type;
    return webcpp::asio_backend::async_initiate<CompletionToken, signature>(
        post_initiation{}, token, executor, std::move(operation));
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
 * Whether an `async_verify` of `Scheme` against the public key `Key` exists: `eddsa_t` against
 * Ed25519's bytes, `ecdsa_sha256_t` against a P-256 public key; the catch-all `async_verify`
 * steps aside where it is true.
 *
 * @tparam Scheme A scheme tag.
 * @tparam Key The public key's type, without its reference and qualifiers.
 */
template <class Scheme, class Key>
inline constexpr bool has_async_verifier_v =
    (std::is_same_v<Scheme, eddsa_t> &&
     std::is_convertible_v<Key const&, std::span<std::uint8_t const>>) ||
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
                      "an Ed25519 key pair signs with crypto::eddsa, a P-256 key pair with "
                      "crypto::ecdsa_sha256.");
    } else {
        check_input<Scheme, Input, typename key_backend<Keypair>::type>();
    }
}

/**
 * A valid input as the operation keeps it until it runs: a message as the view of its bytes, a
 * marker as itself, a view too. Neither copies the bytes, which are the caller's until the
 * completion; a temporary that holds the view, such as `prehashed{digest}` made in the call's
 * argument list, does not have to outlive the call, which a `deferred` operation launches later.
 *
 * @tparam Input A message's type or `prehashed<N>`.
 * @param input The message or the marker.
 * @return The view the operation keeps.
 */
template <class Input>
[[nodiscard]] constexpr auto kept_input(Input const& input) noexcept {
    if constexpr (is_prehashed_v<Input>) {
        return input;
    } else {
        return message_bytes(input);
    }
}

/**
 * Ed25519's `async_verify` once its guard is held, for both public overloads: the engine of a
 * backend that completes by itself, or `crypto::verify` run when the operation is initiated.
 *
 * @tparam Backend The backend.
 * @param executor The executor the completion is posted to.
 * @param signature The signature.
 * @param message The message.
 * @param public_key The public key.
 * @param policy `curves::ed25519::strict`.
 * @param token The completion token.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Executor, class Input, class CompletionToken>
auto async_verify_ed25519(Executor const& executor, std::span<std::uint8_t const> signature,
                          Input const& message, std::span<std::uint8_t const> public_key,
                          [[maybe_unused]] curves::ed25519::strict_t policy,
                          CompletionToken&& token) {
    if constexpr (!can_verify<eddsa_t, Input, std::span<std::uint8_t const>>) {
        check_input<eddsa_t, Input, Backend>();
    } else if constexpr (asynchronous_backend_v<Backend>) {
        return async_engine<Backend>::verify(executor, eddsa, signature, kept_input(message),
                                             public_key, policy,
                                             std::forward<CompletionToken>(token));
    } else {
        return complete_by_post(
            executor, token, [signature, kept = kept_input(message), public_key]() noexcept {
                return ::webcpp::crypto::verify<Backend>(eddsa, signature, kept, public_key,
                                                         curves::ed25519::strict);
            });
    }
}

}  // namespace detail

/**
 * Makes an AES-GCM object, an Ed25519 key pair or a P-256 key pair from its key bytes,
 * asynchronously:
 * `Algorithm::make(key_bytes)` run when the operation is initiated, its result posted to
 * `executor`.
 *
 * The key is read before the call returns on a synchronous backend,
 * later on the browser's: it is the caller's until the completion.
 *
 * @tparam Algorithm A `ciphers::gcm<Cipher>`, a `curves::ed25519::basic_keypair<Backend>` or a
 * `curves::p256::basic_keypair<Backend>`, on any backend that has it; the other algorithms crypto
 * has are not in WebCrypto: call their `make`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param key_bytes `Algorithm::key_size` bytes for AES-GCM, the seed's `seed_size` for an
 * Ed25519 key pair, the secret scalar's `secret_key_size` (32 bytes, big-endian) for a P-256 key
 * pair.
 * @param token The completion token, of signature `void(boost::system::error_code, Algorithm)`;
 * on an error the object is empty, and every member refuses with `invalid_state`
 * (`invalid_key_size`, `invalid_secret_key` for a P-256 scalar 0 or not below the group order,
 * `errc::not_enough_memory`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Algorithm, class Executor, class CompletionToken>
auto async_make(Executor const& executor, std::span<std::uint8_t const> key_bytes,
                CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<Algorithm> && !detail::is_webcrypto_keypair_v<Algorithm>) {
        static_assert(detail::refused_v<Algorithm>,
                      "webcpp::crypto: async_make takes AES-GCM or a key pair of an algorithm "
                      "WebCrypto has (Ed25519, P-256): call the synchronous make for the others.");
    } else {
        using backend = Algorithm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::template make<Algorithm>(
                executor, key_bytes, std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token, [key_bytes]() noexcept { return Algorithm::make(key_bytes); });
        }
    }
}

/**
 * Makes an Ed25519 or a P-256 key pair from a fresh seed or scalar, asynchronously:
 * `Keypair::generate()` run when the operation is initiated (the system's generator is drawn from
 * then), its result posted to `executor`.
 *
 * @tparam Keypair A `curves::ed25519::basic_keypair<Backend>`, by default the family's
 * `curves::ed25519::keypair`, or a `curves::p256::basic_keypair<Backend>`; the other key pairs
 * are not in WebCrypto: call their `generate`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param token The completion token, of signature `void(boost::system::error_code, Keypair)`;
 * on an error the key pair is empty, and every member refuses with `invalid_state`
 * (`entropy_unavailable`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair = curves::ed25519::keypair, class Executor, class CompletionToken>
auto async_generate(Executor const& executor, CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_webcrypto_keypair_v<Keypair>) {
        static_assert(detail::refused_v<Keypair>,
                      "webcpp::crypto: async_generate takes a key pair of an algorithm WebCrypto "
                      "has (Ed25519, P-256): call the synchronous generate for the others.");
    } else {
        using backend = Keypair::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::template generate<Keypair>(
                executor, std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(executor, token,
                                            []() noexcept { return Keypair::generate(); });
        }
    }
}

/**
 * Seals a message in place, asynchronously: `aead.seal` run when the operation is initiated, its
 * result posted to `executor`.
 *
 * `aead` and the spans are the caller's until the completion: a synchronous backend reads and
 * writes them before the call returns, the browser's later. `data_bytes` holds the ciphertext at
 * the completion. A guard's refusal (`invalid_iv_size`, `message_too_long`, `invalid_state`)
 * leaves it untouched, a backend's failure zeroes it, as `seal` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `seal`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param aead The keyed object.
 * @param iv_bytes 1 to `max_iv_size` bytes, never reused under this key.
 * @param additional_data_bytes Authenticated, not encrypted.
 * @param data_bytes The message.
 * @param token The completion token, of signature `void(boost::system::error_code,
 * Gcm::result_type)`: the tag; on an error the zeroed tag.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_seal(Executor const& executor, Gcm& aead, std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<std::remove_cv_t<Gcm>>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_seal takes AES-GCM, the AEAD WebCrypto has: call seal "
                      "for the others.");
    } else {
        using backend = Gcm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::seal(executor, aead, iv_bytes,
                                                       additional_data_bytes, data_bytes,
                                                       std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token, [&aead, iv_bytes, additional_data_bytes, data_bytes]() noexcept {
                    return aead.seal(iv_bytes, additional_data_bytes, data_bytes);
                });
        }
    }
}

/**
 * Opens a message in place, asynchronously: `aead.open` run when the operation is initiated, its
 * result posted to `executor`.
 *
 * `aead` and the spans are the caller's until the completion. `data_bytes` holds the plaintext at
 * a successful completion; a wrong tag (`authentication_failed`) or a backend's failure zeroes
 * it, a guard's refusal leaves it untouched, as `open` does.
 *
 * @tparam Gcm A `ciphers::gcm<Cipher>`; the other AEADs are not in WebCrypto: call their `open`.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param aead The keyed object.
 * @param iv_bytes The IV of the seal.
 * @param additional_data_bytes The additional data of the seal.
 * @param data_bytes The ciphertext.
 * @param tag_bytes The seal's tag, 16 bytes.
 * @param token The completion token, of signature `void(boost::system::error_code)`.
 * @return What the completion token's `async_result` gives.
 */
template <class Gcm, class Executor, class CompletionToken>
auto async_open(Executor const& executor, Gcm& aead, std::span<std::uint8_t const> iv_bytes,
                std::span<std::uint8_t const> additional_data_bytes,
                std::span<std::uint8_t> data_bytes, std::span<std::uint8_t const> tag_bytes,
                CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_gcm_v<std::remove_cv_t<Gcm>>) {
        static_assert(detail::refused_v<Gcm>,
                      "webcpp::crypto: async_open takes AES-GCM, the AEAD WebCrypto has: call open "
                      "for the others.");
    } else {
        using backend = Gcm::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::open(executor, aead, iv_bytes,
                                                       additional_data_bytes, data_bytes, tag_bytes,
                                                       std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token,
                [&aead, iv_bytes, additional_data_bytes, data_bytes, tag_bytes]() noexcept {
                    return aead.open(iv_bytes, additional_data_bytes, data_bytes, tag_bytes);
                });
        }
    }
}

/**
 * Signs with an Ed25519 or a P-256 key pair, asynchronously: `key_pair.sign(scheme, input)` run
 * when the operation is initiated, its result posted to `executor`.
 *
 * Ed25519 signs the message with `crypto::eddsa`; P-256 signs with `crypto::ecdsa_sha256` the
 * message, which it hashes with SHA-256, as WebCrypto's ECDSA with SHA-256 signs, or
 * `crypto::prehashed{digest}` (RFC 6979's nonce: the same key and input give the same signature;
 * S low).
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
 * @tparam Scheme `crypto::eddsa_t` for Ed25519, `crypto::ecdsa_sha256_t` for P-256.
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or for P-256 `crypto::prehashed<32>`.
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param key_pair The key pair.
 * @param scheme `crypto::eddsa` or `crypto::ecdsa_sha256`.
 * @param input The message, or for P-256 `crypto::prehashed{digest}`, its 32-byte SHA-256 digest.
 * @param token The completion token, of signature `void(error_code, signature)`, the signature
 * a `std::array` of 64 bytes (P-256's r then s, IEEE P1363's form, WebCrypto's); on an error it
 * is 64 zeros (`invalid_state`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Keypair, class Executor, class Scheme, class Input, class CompletionToken>
auto async_sign(Executor const& executor, Keypair const& key_pair, Scheme scheme,
                Input const& input, CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!detail::is_webcrypto_keypair_v<Keypair>) {
        static_assert(
            detail::refused_v<Keypair>,
            "webcpp::crypto: async_sign takes a key pair of an algorithm WebCrypto has "
            "(Ed25519, P-256): call the key pair's synchronous signing function for the others.");
    } else if constexpr (!can_sign<Keypair, Scheme, Input>) {
        detail::refuse_async_sign<Keypair, Scheme, Input>();
    } else {
        using backend = Keypair::backend_type;
        if constexpr (detail::asynchronous_backend_v<backend>) {
            return detail::async_engine<backend>::sign(executor, key_pair, scheme,
                                                       detail::kept_input(input),
                                                       std::forward<CompletionToken>(token));
        } else {
            return detail::complete_by_post(
                executor, token, [&key_pair, scheme, kept = detail::kept_input(input)]() noexcept {
                    return key_pair.sign(scheme, kept);
                });
        }
    }
}

/**
 * Verifies an Ed25519 signature (RFC 8032's pure Ed25519), asynchronously, strictly:
 * `crypto::verify<Backend>(crypto::eddsa, signature, message, public_key)` run when the operation
 * is initiated, its result posted to `executor`.
 *
 * The input is checked as `crypto::can_verify` checks it, before anything else: a marker stops
 * the build (Ed25519 signs the message itself). The bytes are the caller's until the completion.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`.
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param scheme `crypto::eddsa`.
 * @param signature 64 bytes.
 * @param message The signed bytes.
 * @param public_key 32 bytes.
 * @param token The completion token, of signature `void(boost::system::error_code)`:
 * `invalid_signature` for a signature of another size, then `invalid_public_key` for a key of
 * another size; `invalid_signature` for a signature that does not verify; `backend_failure`.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor, class Input,
          class CompletionToken>
auto async_verify(Executor const& executor, [[maybe_unused]] eddsa_t scheme,
                  std::span<std::uint8_t const> signature, Input const& message,
                  std::span<std::uint8_t const> public_key, CompletionToken&& token) {
    detail::timing_guard const timing;
    return detail::async_verify_ed25519<Backend>(executor, signature, message, public_key,
                                                 curves::ed25519::strict,
                                                 std::forward<CompletionToken>(token));
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
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`.
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param scheme `crypto::eddsa`.
 * @param signature 64 bytes.
 * @param message The signed bytes.
 * @param public_key 32 bytes.
 * @param policy `curves::ed25519::strict` (libsodium's rules), the only policy declared.
 * @param token The completion token, of signature `void(boost::system::error_code)`, as the
 * overload without a policy completes.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::ed25519>, class Executor, class Input,
          class CompletionToken>
auto async_verify(Executor const& executor, [[maybe_unused]] eddsa_t scheme,
                  std::span<std::uint8_t const> signature, Input const& message,
                  std::span<std::uint8_t const> public_key, curves::ed25519::strict_t policy,
                  CompletionToken&& token) {
    detail::timing_guard const timing;
    return detail::async_verify_ed25519<Backend>(executor, signature, message, public_key, policy,
                                                 std::forward<CompletionToken>(token));
}

/**
 * Verifies a P-256 ECDSA signature over SHA-256, asynchronously:
 * `crypto::verify(crypto::ecdsa_sha256, signature, input, public_key)` run when the operation is
 * initiated, its result posted to `executor`; the message is hashed with SHA-256, as WebCrypto's
 * ECDSA with SHA-256 verifies, or `crypto::prehashed{digest}` gives its digest.
 *
 * A high S and a low S are both accepted, as `crypto::verify` and WebCrypto accept them. The
 * input is checked as `crypto::can_verify` checks it, before anything else: a marker on a backend
 * that completes by itself stops the build. The key and the bytes are the caller's until the
 * completion.
 *
 * @tparam Backend The key's backend, which verifies: deduced from the key, or named first, as on
 * every curve.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam Input A message, bytes that convert to `std::span<std::uint8_t const>`, of any size,
 * empty included, or `crypto::prehashed<32>`.
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param scheme `crypto::ecdsa_sha256`.
 * @param signature 64 bytes, r then s (IEEE P1363's form, WebCrypto's); `curves::p256::from_der`
 * reads DER.
 * @param input The signed message, or `crypto::prehashed{digest}`, its 32-byte SHA-256 digest.
 * @param public_key The signer's public key, validated when it was made.
 * @param token The completion token, of signature `void(boost::system::error_code)`:
 * `invalid_signature` for a signature of another size, an r or an s that is 0 or not below n, and
 * one that does not verify.
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Executor, class Input, class CompletionToken>
auto async_verify(Executor const& executor, [[maybe_unused]] ecdsa_sha256_t scheme,
                  std::span<std::uint8_t const> signature, Input const& input,
                  curves::p256::basic_public_key<Backend> const& public_key,
                  CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (!can_verify<ecdsa_sha256_t, Input, curves::p256::basic_public_key<Backend>>) {
        detail::check_input<ecdsa_sha256_t, Input, Backend>();
    } else if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::verify(executor, scheme, signature,
                                                     detail::kept_input(input), public_key,
                                                     std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(executor, token,
                                        [signature, kept = detail::kept_input(input),
                                         &public_key]() noexcept -> boost::system::result<void> {
                                            if (signature.size() != curves::p256::signature_size) {
                                                return error::invalid_signature;
                                            }
                                            return ::webcpp::crypto::verify(
                                                ecdsa_sha256,
                                                signature.first<curves::p256::signature_size>(),
                                                kept, public_key);
                                        });
    }
}

/**
 * Stops the build: no `async_verify` checks a signature of `Scheme` against this public key.
 *
 * The asynchronous family has the algorithms WebCrypto has: Ed25519's and P-256's overloads above
 * are chosen for their keys; this one only when neither is, and it names them.
 *
 * @tparam Backend Ignored: the first template parameter, as on every `async_verify`.
 * @tparam Executor The executor's type.
 * @tparam Scheme A scheme tag.
 * @tparam Signature The signature's type.
 * @tparam Input The input's type.
 * @tparam PublicKey The public key's type.
 * @tparam CompletionToken The completion token's type.
 * @param executor The executor.
 * @param scheme The scheme.
 * @param signature The signature.
 * @param input The message or the marker.
 * @param public_key The public key.
 * @param token The completion token.
 */
template <class Backend = void, class Executor, class Scheme, class Signature, class Input,
          class PublicKey, class CompletionToken>
    requires(detail::is_scheme_v<Scheme> &&
             !detail::has_async_verifier_v<Scheme, std::remove_cvref_t<PublicKey>>)
void async_verify([[maybe_unused]] Executor const& executor, [[maybe_unused]] Scheme scheme,
                  [[maybe_unused]] Signature const& signature, [[maybe_unused]] Input const& input,
                  [[maybe_unused]] PublicKey const& public_key,
                  [[maybe_unused]] CompletionToken&& token) {
    static_assert(detail::refused_v<Scheme>,
                  "webcpp::crypto: async_verify takes crypto::eddsa with Ed25519's 32-byte key or "
                  "crypto::ecdsa_sha256 with a curves::p256::basic_public_key, the algorithms "
                  "WebCrypto has: call crypto::verify for the others.");
}

/**
 * Agrees an X25519 shared secret, asynchronously: `curves::x25519::agree<Backend>` run when the
 * operation is initiated, its result posted to `executor`.
 *
 * The spans are the caller's until the completion.
 *
 * @tparam Backend The backend; by default the asynchronous family's.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param secret_key 32 bytes.
 * @param peer_public_key 32 bytes.
 * @param token The completion token, of signature `void(boost::system::error_code, secret<32>)`:
 * the shared secret; on an error a secret of zeros (`invalid_key_size`, `invalid_public_key`,
 * `weak_public_key`, `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Backend = default_async_backend_t<families::x25519>, class Executor,
          class CompletionToken>
auto async_agree(Executor const& executor, std::span<std::uint8_t const> secret_key,
                 std::span<std::uint8_t const> peer_public_key, CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::agree(executor, secret_key, peer_public_key,
                                                    std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(executor, token, [secret_key, peer_public_key]() noexcept {
            return curves::x25519::agree<Backend>(secret_key, peer_public_key);
        });
    }
}

/**
 * Agrees a P-256 shared secret, ECDH's raw x coordinate, asynchronously:
 * `key_pair.ecdh_x(peer_public_key)` run when the operation is initiated, its result posted to
 * `executor`, as WebCrypto's `deriveBits` with ECDH on P-256 gives its 256 bits.
 *
 * The x coordinate is not a key: a protocol hashes it into its keys (with HKDF, for instance).
 * The key pair and the peer's key are the caller's until the completion.
 *
 * @tparam Backend The backend of the key pair and of the peer's key.
 * @tparam Executor The executor's type, an Asio executor (an `io_context`'s or a strand's).
 * @tparam CompletionToken Any completion token for the signature `token` states.
 * @param executor The executor the completion is posted to.
 * @param key_pair This side's key pair.
 * @param peer_public_key The peer's public key, validated when it was made.
 * @param token The completion token, of signature `void(boost::system::error_code, secret<32>)`:
 * the shared x, big-endian; on an error a secret of zeros (`invalid_state` for an empty key pair,
 * `backend_failure`).
 * @return What the completion token's `async_result` gives.
 */
template <class Backend, class Executor, class CompletionToken>
auto async_agree(Executor const& executor, curves::p256::basic_keypair<Backend> const& key_pair,
                 curves::p256::basic_public_key<Backend> const& peer_public_key,
                 CompletionToken&& token) {
    detail::timing_guard const timing;
    if constexpr (detail::asynchronous_backend_v<Backend>) {
        return detail::async_engine<Backend>::agree(executor, key_pair, peer_public_key,
                                                    std::forward<CompletionToken>(token));
    } else {
        return detail::complete_by_post(executor, token, [&key_pair, &peer_public_key]() noexcept {
            return key_pair.ecdh_x(peer_public_key);
        });
    }
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_ASYNC_HPP
