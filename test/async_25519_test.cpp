// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519's and X25519's asynchronous functions on libsodium, on a callback and in a coroutine.
// async_sign and async_verify take the scheme, crypto::eddsa, and the synchronous calls' inputs,
// the message and, for async_verify, the policy before the token, strict by default:
// - async_rfc8032: RFC 8032 section 7.1's tests 1, 2 and 3 through async_from_secret and async_sign
//   give the RFC's signatures and the synchronous ones, and async_verify accepts them, with the
//   backend named and its policy given, and with the defaults; each completion arrives after the
//   initiating call returned.
// - async_verify_changed: a changed byte of the signature or of the message completes with
//   invalid_signature; a signature of 63 bytes, and the key's bytes where the signature goes, as
//   the order before the signature came first (key, message, signature) put them, are refused by
//   ed25519::signature::from_bytes, before any verify.
// - async_generate: async_generate gives a key pair whose signature verifies, on the default
//   backend and on libsodium named.
// - async_from_secret_refused: a seed of 31 bytes completes with invalid_key_size and an empty key
//   pair, which refuses every member with invalid_state (review focus 5), async_sign on it too,
//   with a signature of zeros.
// - async_rfc7748: section 6.1's Alice and Bob, made by async_from_secret, member and free, give
//   the RFC's public keys and, through async_agree, member and free, with the default backend and
//   with libsodium named, the RFC's shared secret, as the synchronous agree does; a peer key of
//   low order completes with weak_public_key and a secret of zeros; a short secret key with
//   invalid_key_size and an empty key pair, whose async_agree completes with invalid_state;
//   async_generate, member and free, gives a key pair that agrees with Alice.
// - async_destroyed: the key pairs, the message and the keys destroyed after the initiating call
//   returns and before the completion: a synchronous backend has read them already, so the
//   completion gives the right result (the browser's backend will read them later: they are the
//   caller's until the completion, as the documentation says).
// - async_coroutine: the same in one coroutine of the context.
// - async_four_forms: each Ed25519 operation in its four forms (design D9), the member and the
//   free, synchronous and asynchronous, gives the same result: from_secret (the same public key,
//   and the same refusal of a short seed), generate (a key pair whose signature verifies), sign
//   (RFC 8032's signature, an ed25519::signature, and an empty key pair's invalid_state and
//   zeros), verify with the defaults and with the backend and the policy named (each accepts the
//   signature, received as a std::vector and made into the type with from_bytes, and refuses a
//   changed one with invalid_signature; from_bytes refuses 63 and 65 bytes with
//   invalid_signature); each asynchronous completion arrives after the initiating call returned.
// - eddsa_prehashed_async: under crypto::eddsa_prehashed, RFC 8032 section 7.3's key pair signs
//   the marker of "abc"'s SHA-512 through key.async_sign and crypto::async_sign into the
//   synchronous signature, which async_verify, member and free, accepts, with the defaults and with
//   the backend and the policy named; each completion arrives after the initiating call returned.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
namespace ed25519 = webcpp::crypto::curves::ed25519;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace test = webcpp::test;

namespace {

using keypair = ed25519::basic_keypair<crypto::backends::sodium>;
using signature_type = ed25519::signature;

// The signature of 64 bytes, as one received is made.
signature_type typed(std::span<std::uint8_t const> signature_bytes) {
    auto made = signature_type::from_bytes(signature_bytes);
    BOOST_TEST(made.has_value());
    return made ? *made : signature_type{};
}

// What a completion saw: its calls, whether the initiating call had returned, its error code and
// its value, if it has one.
template <class... Value>
struct completed {
    int calls = 0;
    bool after_return = false;
    boost::system::error_code code;
    std::optional<std::tuple<Value...>> value;
};

// Starts `start(executor, token)` with a callback, runs the context and returns what the
// callback saw: one completion, after the initiating call returned.
template <class... Value, class Start>
completed<Value...> complete(asio::io_context& context, Start start) {
    completed<Value...> done;
    bool returned = false;
    start(context.get_executor(),
          [&done, &returned](boost::system::error_code code, Value... value) {
              ++done.calls;
              done.after_return = returned;
              done.code = code;
              done.value = std::tuple<Value...>(std::move(value)...);
          });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(done.after_return);
    return done;
}

// The completion of an operation with no value.
template <class Start>
boost::system::error_code complete_code(asio::io_context& context, Start start) {
    completed<> done;
    bool returned = false;
    start(context.get_executor(), [&done, &returned](boost::system::error_code code) {
        ++done.calls;
        done.after_return = returned;
        done.code = code;
    });
    returned = true;
    BOOST_TEST_EQ(done.calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(done.calls, 1);
    BOOST_TEST(done.after_return);
    return done.code;
}

/** One test of RFC 8032 section 7.1, as the RFC writes it. */
struct rfc8032_case {
    std::string_view secret_key;
    std::string_view public_key;
    std::string_view message;
    std::string_view signature;
};

// clang-format off
constexpr auto rfc8032_cases = std::to_array<rfc8032_case>({
    {.secret_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     .public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     .message = "",
     .signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {.secret_key = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     .public_key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     .message = "72",
     .signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {.secret_key = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     .public_key = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     .message = "af82",
     .signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
});
// clang-format on

// async_verify of eddsa takes the typed key alone: bytes fall to the catch-all
// (messages/async_verify_eddsa_bytes_key).
static_assert(crypto::detail::has_async_verifier_v<crypto::eddsa_t, ed25519::public_key>);
static_assert(!crypto::detail::has_async_verifier_v<crypto::eddsa_t, std::array<std::uint8_t, 32>>);
static_assert(
    !crypto::detail::has_async_verifier_v<crypto::eddsa_t, std::span<std::uint8_t const>>);
static_assert(crypto::detail::has_async_verifier_v<crypto::eddsa_prehashed_t, ed25519::public_key>);
static_assert(
    !crypto::detail::has_async_verifier_v<crypto::eddsa_prehashed_t, std::array<std::uint8_t, 32>>);

/**
 * The public key of a case's hex, 32 bytes; a key not made throws (or, without exceptions, ends
 * the program) through `value()`.
 */
ed25519::public_key key_of(std::string_view hex) {
    auto const made = ed25519::public_key::from_bytes(test::from_hex(hex));
    BOOST_TEST(made.has_value());
    return made.value();
}

/** Whether every byte of `bytes` is zero. */
template <class Bytes>
bool all_zero(Bytes const& bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

void async_rfc8032(asio::io_context& context) {
    for (auto const& tested : rfc8032_cases) {
        auto const seed = test::from_hex(tested.secret_key);
        auto const public_key = key_of(tested.public_key);
        auto const message = test::from_hex(tested.message);
        auto const expected = test::from_hex(tested.signature);

        auto made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_from_secret<keypair>(executor, seed,
                                                      std::forward<decltype(token)>(token));
        });
        BOOST_TEST(!made.code);
        if (!BOOST_TEST(made.value.has_value())) {
            continue;
        }
        auto& key = std::get<0>(*made.value);
        auto const signed_async =
            complete<signature_type>(context, [&](auto const& executor, auto&& token) {
                return crypto::async_sign(executor, key, crypto::eddsa, message,
                                          std::forward<decltype(token)>(token));
            });
        BOOST_TEST(!signed_async.code);
        if (!BOOST_TEST(signed_async.value.has_value())) {
            continue;
        }
        auto const& signature = std::get<0>(*signed_async.value);
        BOOST_TEST(std::ranges::equal(signature.bytes(), expected));
        auto const signed_sync = key.sign(crypto::eddsa, message);
        BOOST_TEST(signed_sync.has_value() && *signed_sync == signature);
        auto const verified = complete_code(context, [&](auto const& executor, auto&& token) {
            return crypto::async_verify<crypto::backends::sodium>(
                executor, crypto::eddsa, signature, message, public_key, ed25519::strict,
                std::forward<decltype(token)>(token));
        });
        BOOST_TEST(!verified);
        // The defaults name the same backend.
        auto const verified_default =
            complete_code(context, [&](auto const& executor, auto&& token) {
                return crypto::async_verify(executor, crypto::eddsa, signature, message, public_key,
                                            std::forward<decltype(token)>(token));
            });
        BOOST_TEST(!verified_default);
    }
}

void async_verify_changed(asio::io_context& context) {
    auto const& tested = rfc8032_cases[2];
    auto const public_key = key_of(tested.public_key);
    auto message = test::from_hex(tested.message);
    auto signature = test::from_hex(tested.signature);
    auto const verify = [&](ed25519::public_key const& key,
                            std::span<std::uint8_t const> signed_bytes) {
        return complete_code(context, [&](auto const& executor, auto&& token) {
            return crypto::async_verify(executor, crypto::eddsa, typed(signed_bytes), message, key,
                                        std::forward<decltype(token)>(token));
        });
    };
    BOOST_TEST(!verify(public_key, signature));
    signature[10] ^= 1U;
    BOOST_TEST(verify(public_key, signature) == crypto::error::invalid_signature);
    signature[10] ^= 1U;
    message[0] ^= 1U;
    BOOST_TEST(verify(public_key, signature) == crypto::error::invalid_signature);
    message[0] ^= 1U;
    BOOST_TEST(!verify(public_key, signature));
    BOOST_TEST(signature_type::from_bytes(std::span(signature).first(63)).error() ==
               crypto::error::invalid_signature);
    // The order before the signature came first: the 32-byte key where the signature goes.
    BOOST_TEST(signature_type::from_bytes(public_key.bytes()).error() ==
               crypto::error::invalid_signature);
}

template <class Keypair>
void generated(asio::io_context& context) {
    auto made = complete<Keypair>(context, [](auto const& executor, auto&& token) {
        return crypto::async_generate<Keypair>(executor, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    if (!BOOST_TEST(made.value.has_value())) {
        return;
    }
    auto& key = std::get<0>(*made.value);
    std::array<std::uint8_t, 5> const message{1, 2, 3, 4, 5};
    auto const public_key = key.public_key();
    auto const signature = key.sign(crypto::eddsa, message);
    if (!BOOST_TEST(public_key.has_value()) || !BOOST_TEST(signature.has_value())) {
        return;
    }
    auto const verified_sync = crypto::verify<typename Keypair::backend_type>(
        crypto::eddsa, *signature, message, *public_key, ed25519::strict);
    BOOST_TEST(verified_sync.has_value());
    auto const signed_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key, crypto::eddsa, message,
                                      std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!signed_async.code);
    BOOST_TEST(signed_async.value.has_value() && std::get<0>(*signed_async.value) == *signature);
    auto const verified = complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, crypto::eddsa, *signature, message, *public_key,
                                    std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!verified);
}

void async_generate(asio::io_context& context) {
    generated<ed25519::keypair>(context);
    generated<keypair>(context);
}

void async_from_secret_refused(asio::io_context& context) {
    std::array<std::uint8_t, 32> const seed{7};
    auto const made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_secret<keypair>(executor, std::span(seed).first(31),
                                                  std::forward<decltype(token)>(token));
    });
    BOOST_TEST(made.code == crypto::error::invalid_key_size);
    if (!BOOST_TEST(made.value.has_value())) {
        return;
    }
    auto const& empty = std::get<0>(*made.value);
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    BOOST_TEST(empty.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(empty.sign(crypto::eddsa, message).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.to_x25519().error() == crypto::error::invalid_state);
    auto const signed_empty =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, empty, crypto::eddsa, message,
                                      std::forward<decltype(token)>(token));
        });
    BOOST_TEST(signed_empty.code == crypto::error::invalid_state);
    if (BOOST_TEST(signed_empty.value.has_value())) {
        BOOST_TEST(all_zero(std::get<0>(*signed_empty.value).bytes()));
    }
}

using x25519_keypair = x25519::basic_keypair<crypto::backends::sodium>;

constexpr std::string_view alice_secret_hex =
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
constexpr std::string_view alice_public_hex =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
constexpr std::string_view bob_secret_hex =
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
constexpr std::string_view bob_public_hex =
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
constexpr std::string_view x25519_shared_hex =
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/** The X25519 public key of a hex string of 32 bytes. */
x25519::public_key x25519_key_of(std::string_view hex) {
    auto const made = x25519::public_key::from_bytes(test::from_hex(hex));
    BOOST_TEST(made.has_value());
    return made.value();
}

// The shared secret of `key_pair` and `peer` through async_agree, the member and the free, each
// with the default backend; both complete with `expected_code` and, without an error, `expected`.
template <class Keypair>
void check_async_agree(asio::io_context& context, Keypair const& key_pair,
                       x25519::public_key const& peer, std::span<std::uint8_t const> expected,
                       boost::system::error_code expected_code) {
    auto const member =
        complete<crypto::secret<32>>(context, [&](auto const& executor, auto&& token) {
            return key_pair.async_agree(executor, peer, std::forward<decltype(token)>(token));
        });
    auto const free = complete<crypto::secret<32>>(context, [&](auto const& executor,
                                                                auto&& token) {
        return crypto::async_agree(executor, key_pair, peer, std::forward<decltype(token)>(token));
    });
    for (auto const* done : {&member, &free}) {
        BOOST_TEST(done->code == expected_code);
        if (!BOOST_TEST(done->value.has_value())) {
            continue;
        }
        auto const bytes = std::get<0>(*done->value).bytes();
        if (expected_code) {
            BOOST_TEST(all_zero(bytes));
        } else {
            BOOST_TEST(std::ranges::equal(bytes, expected));
        }
    }
}

// The refusals through async_agree: a peer key of low order, and an empty key pair, which a short
// secret key's async_from_secret gives.
void async_x25519_refused(asio::io_context& context, std::span<std::uint8_t const> alice_secret,
                          x25519::public_key const& bob_public) {
    // Wycheproof x25519_test.json, tcId 63: a public key of order 8, whose shared secret is 0.
    auto const weak_key = x25519::keypair::from_secret(
        test::from_hex("e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272"));
    if (BOOST_TEST(weak_key.has_value())) {
        check_async_agree(
            context, *weak_key,
            x25519_key_of("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"), {},
            crypto::error::weak_public_key);
    }
    auto const short_key =
        complete<x25519::keypair>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_from_secret<x25519::keypair>(executor, alice_secret.first(31),
                                                              std::forward<decltype(token)>(token));
        });
    BOOST_TEST(short_key.code == crypto::error::invalid_key_size);
    if (BOOST_TEST(short_key.value.has_value())) {
        auto const& empty = std::get<0>(*short_key.value);
        BOOST_TEST(empty.public_key().error() == crypto::error::invalid_state);
        BOOST_TEST(empty.secret().error() == crypto::error::invalid_state);
        check_async_agree(context, empty, bob_public, {}, crypto::error::invalid_state);
    }
}

// async_generate, member and free: a key pair that agrees with Alice as she agrees with it.
void async_x25519_generated(asio::io_context& context, x25519::keypair const& alice,
                            x25519::public_key const& alice_public) {
    auto const generated_member =
        complete<x25519::keypair>(context, [&](auto const& executor, auto&& token) {
            return x25519::keypair::async_generate(executor, std::forward<decltype(token)>(token));
        });
    auto const generated_free =
        complete<x25519::keypair>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_generate<x25519::keypair>(executor,
                                                           std::forward<decltype(token)>(token));
        });
    for (auto const* generated : {&generated_member, &generated_free}) {
        BOOST_TEST(!generated->code);
        if (!BOOST_TEST(generated->value.has_value())) {
            continue;
        }
        auto const& key = std::get<0>(*generated->value);
        auto const own = key.public_key();
        auto const theirs = key.agree(alice_public);
        if (BOOST_TEST(own.has_value()) && BOOST_TEST(theirs.has_value())) {
            check_async_agree(context, alice, *own, theirs->bytes(), {});
        }
    }
}

void async_rfc7748(asio::io_context& context) {
    auto const alice_secret = test::from_hex(alice_secret_hex);
    auto const bob_secret = test::from_hex(bob_secret_hex);
    auto const shared = test::from_hex(x25519_shared_hex);
    auto alice_made = complete<x25519::keypair>(context, [&](auto const& executor, auto&& token) {
        return x25519::keypair::async_from_secret(executor, alice_secret,
                                                  std::forward<decltype(token)>(token));
    });
    auto bob_made = complete<x25519_keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_secret<x25519_keypair>(executor, bob_secret,
                                                         std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!alice_made.code);
    BOOST_TEST(!bob_made.code);
    if (!BOOST_TEST(alice_made.value.has_value()) || !BOOST_TEST(bob_made.value.has_value())) {
        return;
    }
    auto const& alice = std::get<0>(*alice_made.value);
    auto const& bob = std::get<0>(*bob_made.value);
    auto const alice_public = x25519_key_of(alice_public_hex);
    auto const bob_public = x25519_key_of(bob_public_hex);
    BOOST_TEST(alice.public_key() == alice_public);
    BOOST_TEST(bob.public_key() == bob_public);
    check_async_agree(context, alice, bob_public, shared, {});
    check_async_agree(context, bob, alice_public, shared, {});
    auto const synchronous = alice.agree(bob_public);
    BOOST_TEST(synchronous.has_value() && std::ranges::equal(synchronous->bytes(), shared));
    // Named backend.
    auto const named =
        complete<crypto::secret<32>>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_agree<crypto::backends::sodium>(
                executor, bob, alice_public, std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!named.code);
    async_x25519_refused(context, alice_secret, bob_public);
    async_x25519_generated(context, alice, alice_public);
}

void async_destroyed(asio::io_context& context) {
    auto const& tested = rfc8032_cases[0];
    auto const expected = test::from_hex(tested.signature);
    signature_type signature{};
    boost::system::error_code sign_code;
    boost::system::error_code agree_code;
    std::array<std::uint8_t, 32> shared{};
    {
        auto key = keypair::from_secret(test::from_hex(tested.secret_key));
        auto const message =
            std::make_unique<std::vector<std::uint8_t>>(test::from_hex(tested.message));
        auto alice = x25519::keypair::from_secret(test::from_hex(alice_secret_hex));
        auto const peer = std::make_unique<x25519::public_key>(x25519_key_of(bob_public_hex));
        if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(alice.has_value())) {
            return;
        }
        crypto::async_sign(context.get_executor(), *key, crypto::eddsa, *message,
                           [&](boost::system::error_code code, signature_type done) {
                               sign_code = code;
                               signature = done;
                           });
        crypto::async_agree(context.get_executor(), *alice, *peer,
                            [&](boost::system::error_code code, crypto::secret<32> done) {
                                agree_code = code;
                                std::ranges::copy(done.bytes(), shared.begin());
                            });
        // Everything the calls read goes out of scope here, before the completions.
    }
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(!sign_code);
    BOOST_TEST(std::ranges::equal(signature.bytes(), expected));
    BOOST_TEST(!agree_code);
    BOOST_TEST(std::ranges::equal(shared, test::from_hex(x25519_shared_hex)));
}

void async_coroutine(asio::io_context& context) {
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const executor = co_await asio::this_coro::executor;
            auto const& tested = rfc8032_cases[1];
            auto const seed = test::from_hex(tested.secret_key);
            auto const public_key = key_of(tested.public_key);
            auto const message = test::from_hex(tested.message);
            auto made_code_result = co_await crypto::async_from_secret<keypair>(
                executor, seed, asio::as_tuple(asio::use_awaitable));
            auto& [made_code, key] = made_code_result;
            BOOST_TEST(!made_code);
            auto [sign_code, signature] = co_await crypto::async_sign(
                executor, key, crypto::eddsa, message, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!sign_code);
            BOOST_TEST(std::ranges::equal(signature.bytes(), test::from_hex(tested.signature)));
            auto [verify_code] =
                co_await crypto::async_verify(executor, crypto::eddsa, signature, message,
                                              public_key, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!verify_code);
            auto generate_code_result =
                co_await crypto::async_generate(executor, asio::as_tuple(asio::use_awaitable));
            auto& [generate_code, generated_key] = generate_code_result;
            BOOST_TEST(!generate_code);
            BOOST_TEST(generated_key.public_key().has_value());
            auto alice_made_result = co_await x25519::keypair::async_from_secret(
                executor, test::from_hex(alice_secret_hex), asio::as_tuple(asio::use_awaitable));
            auto& [alice_code, alice] = alice_made_result;
            BOOST_TEST(!alice_code);
            auto agree_code_result = co_await alice.async_agree(
                executor, x25519_key_of(bob_public_hex), asio::as_tuple(asio::use_awaitable));
            auto& [agree_code, shared] = agree_code_result;
            BOOST_TEST(!agree_code);
            BOOST_TEST(std::ranges::equal(shared.bytes(), test::from_hex(x25519_shared_hex)));
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

// from_secret in its four forms: the same key pair, and the same refusal of a short seed.
void four_forms_from_secret(asio::io_context& context, std::span<std::uint8_t const> seed,
                            ed25519::public_key const& expected) {
    auto const member_sync = keypair::from_secret(seed);
    auto const free_sync = crypto::from_secret<keypair>(seed);
    auto const member_async = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return keypair::async_from_secret(executor, seed, std::forward<decltype(token)>(token));
    });
    auto const free_async = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_secret<keypair>(executor, seed,
                                                  std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!member_async.code);
    BOOST_TEST(!free_async.code);
    auto const public_of = [](keypair const& key) { return key.public_key().value(); };
    BOOST_TEST(member_sync.has_value() && public_of(*member_sync) == expected);
    BOOST_TEST(free_sync.has_value() && public_of(*free_sync) == expected);
    BOOST_TEST(member_async.value.has_value() &&
               public_of(std::get<0>(*member_async.value)) == expected);
    BOOST_TEST(free_async.value.has_value() &&
               public_of(std::get<0>(*free_async.value)) == expected);
    auto const short_seed = seed.first(31);
    BOOST_TEST(keypair::from_secret(short_seed).error() == crypto::error::invalid_key_size);
    BOOST_TEST(crypto::from_secret<keypair>(short_seed).error() == crypto::error::invalid_key_size);
    BOOST_TEST(complete<keypair>(context, [&](auto const& executor, auto&& token) {
                   return keypair::async_from_secret(executor, short_seed,
                                                     std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
    BOOST_TEST(complete<keypair>(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_from_secret<keypair>(executor, short_seed,
                                                             std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
}

// Whether a generated key pair signs a message its own public key verifies.
bool signs_and_verifies(keypair const& key) {
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    auto const signature = key.sign(crypto::eddsa, message);
    auto const own = key.public_key();
    return signature.has_value() && own.has_value() &&
           own->verify(crypto::eddsa, *signature, message).has_value();
}

// generate in its four forms: each a key pair whose signature verifies.
void four_forms_generate(asio::io_context& context) {
    auto const member_sync = keypair::generate();
    auto const free_sync = crypto::generate<keypair>();
    auto const member_async = complete<keypair>(context, [](auto const& executor, auto&& token) {
        return keypair::async_generate(executor, std::forward<decltype(token)>(token));
    });
    auto const free_async = complete<keypair>(context, [](auto const& executor, auto&& token) {
        return crypto::async_generate<keypair>(executor, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!member_async.code);
    BOOST_TEST(!free_async.code);
    BOOST_TEST(member_sync.has_value() && signs_and_verifies(*member_sync));
    BOOST_TEST(free_sync.has_value() && signs_and_verifies(*free_sync));
    BOOST_TEST(member_async.value.has_value() &&
               signs_and_verifies(std::get<0>(*member_async.value)));
    BOOST_TEST(free_async.value.has_value() && signs_and_verifies(std::get<0>(*free_async.value)));
}

// sign in its four forms: the same signature, or the same refusal and zeros.
void check_four_signatures(asio::io_context& context, keypair const& key,
                           std::span<std::uint8_t const> message,
                           std::span<std::uint8_t const> expected,
                           boost::system::error_code expected_code) {
    auto const member_sync = key.sign(crypto::eddsa, message);
    auto const free_sync = crypto::sign(key, crypto::eddsa, message);
    auto const member_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return key.async_sign(executor, crypto::eddsa, message,
                                  std::forward<decltype(token)>(token));
        });
    auto const free_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key, crypto::eddsa, message,
                                      std::forward<decltype(token)>(token));
        });
    BOOST_TEST(member_async.code == expected_code);
    BOOST_TEST(free_async.code == expected_code);
    if (!BOOST_TEST(member_async.value.has_value()) || !BOOST_TEST(free_async.value.has_value())) {
        return;
    }
    if (expected_code) {
        BOOST_TEST(member_sync.error() == expected_code);
        BOOST_TEST(free_sync.error() == expected_code);
        BOOST_TEST(all_zero(std::get<0>(*member_async.value).bytes()));
        BOOST_TEST(all_zero(std::get<0>(*free_async.value).bytes()));
        return;
    }
    if (!BOOST_TEST(member_sync.has_value()) || !BOOST_TEST(free_sync.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(member_sync->bytes(), expected));
    BOOST_TEST(*free_sync == *member_sync);
    BOOST_TEST(std::get<0>(*member_async.value) == *member_sync);
    BOOST_TEST(std::get<0>(*free_async.value) == *member_sync);
}

// verify in its four forms, with the defaults and with the backend and the policy named: the
// same answer.
void check_four_verifications(asio::io_context& context, ed25519::public_key const& key,
                              signature_type const& signature,
                              std::span<std::uint8_t const> message,
                              boost::system::error_code expected_code) {
    using crypto::backends::sodium;
    auto const code_of = [](boost::system::result<void> const& done) {
        return done ? boost::system::error_code{} : done.error();
    };
    BOOST_TEST(code_of(key.verify(crypto::eddsa, signature, message)) == expected_code);
    BOOST_TEST(code_of(key.verify<sodium>(crypto::eddsa, signature, message, ed25519::strict)) ==
               expected_code);
    BOOST_TEST(code_of(crypto::verify(crypto::eddsa, signature, message, key)) == expected_code);
    BOOST_TEST(code_of(crypto::verify<sodium>(crypto::eddsa, signature, message, key,
                                              ed25519::strict)) == expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return key.async_verify(executor, crypto::eddsa, signature, message,
                                           std::forward<decltype(token)>(token));
               }) == expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return key.async_verify<sodium>(executor, crypto::eddsa, signature, message,
                                                   ed25519::strict,
                                                   std::forward<decltype(token)>(token));
               }) == expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_verify(executor, crypto::eddsa, signature, message, key,
                                               std::forward<decltype(token)>(token));
               }) == expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_verify<sodium>(executor, crypto::eddsa, signature, message,
                                                       key, ed25519::strict,
                                                       std::forward<decltype(token)>(token));
               }) == expected_code);
}

void async_four_forms(asio::io_context& context) {
    auto const& tested = rfc8032_cases[2];
    auto const seed = test::from_hex(tested.secret_key);
    auto const public_key = key_of(tested.public_key);
    auto const message = test::from_hex(tested.message);
    auto signature = test::from_hex(tested.signature);
    four_forms_from_secret(context, seed, public_key);
    four_forms_generate(context);
    auto key = keypair::from_secret(seed);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    check_four_signatures(context, *key, message, signature, {});
    // The signature received as a std::vector, made into the type.
    check_four_verifications(context, public_key, typed(signature), message, {});
    auto longer = signature;
    longer.push_back(0);
    BOOST_TEST(signature_type::from_bytes(longer).error() == crypto::error::invalid_signature);
    BOOST_TEST(
        signature_type::from_bytes(std::span<std::uint8_t const>(signature).first(63)).error() ==
        crypto::error::invalid_signature);
    signature[10] ^= 1U;
    check_four_verifications(context, public_key, typed(signature), message,
                             crypto::error::invalid_signature);
    [[maybe_unused]] keypair const taken(std::move(*key));
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the empty key pair
    check_four_signatures(context, *key, message, signature, crypto::error::invalid_state);
}

void eddsa_prehashed_async(asio::io_context& context) {
    using crypto::backends::sodium;
    // RFC 8032 section 7.3, TEST abc.
    auto const key =
        keypair::from_secret(
            test::from_hex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"))
            .value();
    auto const public_key =
        key_of("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    std::array<std::uint8_t, 3> const abc{0x61, 0x62, 0x63};
    webcpp::hash::sha2_512 hasher;
    hasher.update(abc.data(), abc.size());
    boost::hash2::digest<64> const digest = hasher.result();
    crypto::prehashed const marker{digest};
    auto const expected = key.sign(crypto::eddsa_prehashed, marker);
    if (!BOOST_TEST(expected.has_value())) {
        return;
    }
    // clang-format off
    BOOST_TEST(std::ranges::equal(expected->bytes(), test::from_hex("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")));
    // clang-format on

    auto const signed_member =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return key.async_sign(executor, crypto::eddsa_prehashed, marker,
                                  std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!signed_member.code);
    BOOST_TEST(signed_member.value && std::get<0>(*signed_member.value) == *expected);
    auto const signed_free =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key, crypto::eddsa_prehashed, marker,
                                      std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!signed_free.code);
    BOOST_TEST(signed_free.value && std::get<0>(*signed_free.value) == *expected);

    BOOST_TEST(!complete_code(context, [&](auto const& executor, auto&& token) {
        return public_key.async_verify(executor, crypto::eddsa_prehashed, *expected, marker,
                                       std::forward<decltype(token)>(token));
    }));
    BOOST_TEST(!complete_code(context, [&](auto const& executor, auto&& token) {
        return public_key.async_verify<sodium>(executor, crypto::eddsa_prehashed, *expected, marker,
                                               ed25519::strict,
                                               std::forward<decltype(token)>(token));
    }));
    BOOST_TEST(!complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, crypto::eddsa_prehashed, *expected, marker,
                                    public_key, std::forward<decltype(token)>(token));
    }));
    BOOST_TEST(!complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify<sodium>(executor, crypto::eddsa_prehashed, *expected, marker,
                                            public_key, ed25519::strict,
                                            std::forward<decltype(token)>(token));
    }));
    // The pure scheme's signature of the same message is refused under eddsa_prehashed.
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_verify(executor, crypto::eddsa_prehashed,
                                               key.sign(crypto::eddsa, abc).value(), marker,
                                               public_key, std::forward<decltype(token)>(token));
               }) == crypto::error::invalid_signature);
}

}  // namespace

int main() {
    asio::io_context context;
    async_rfc8032(context);
    async_verify_changed(context);
    async_generate(context);
    async_from_secret_refused(context);
    async_rfc7748(context);
    async_destroyed(context);
    async_coroutine(context);
    async_four_forms(context);
    eddsa_prehashed_async(context);
    return webcpp::test::exit_status(boost::report_errors());
}
