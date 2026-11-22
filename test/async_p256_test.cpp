// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256's asynchronous functions on BearSSL, on a callback and in a coroutine. async_sign and
// async_verify take the message and hash it with SHA-256, as WebCrypto's ECDSA with SHA-256 does;
// the synchronous answers they are checked against are sign_ecdsa and verify_ecdsa of its digest.
// - async_rfc6979: RFC 6979 section A.2.5's key through async_make, its messages "sample" and
//   "test" through async_sign give the RFC's signatures and the synchronous ones, and async_verify
//   accepts them; each completion arrives after the initiating call returned.
// - async_wycheproof_ecdsa: the first 50 valid cases of Wycheproof's ECDSA P-256 SHA-256 file in
//   WebCrypto's form (IEEE P1363's r || s) verify through async_verify as through verify_ecdsa;
//   with a changed byte of the message both refuse them with invalid_signature.
// - async_wycheproof_ecdh: the first 50 valid cases of Wycheproof's ECDH P-256 file on points
//   through async_make and async_agree give the file's shared x and ecdh_x's.
// - async_verify_refused: a changed byte of the signature, a signature of 63 bytes and one whose
//   r is 0 complete with invalid_signature.
// - async_generate: async_generate gives a key pair whose signature verifies, on the default
//   backend and on BearSSL named.
// - async_make_refused: a scalar of 31 bytes completes with invalid_key_size, the group order
//   with invalid_secret_key, each with an empty key pair, which refuses every member with
//   invalid_state (review focus 5), async_sign and async_agree on it too, with zeros.
// - async_destroyed: the key pair, the message and the peer's key destroyed after the initiating
//   call returns and before the completion: a synchronous backend has read them already, so the
//   completion gives the right result.
// - async_coroutine: the same in one coroutine of the context.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/p256_data.hpp"
#include "support/test_data.hpp"

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/io_context.hpp>
#include <webcpp/asio/this_coro.hpp>
#include <webcpp/asio/use_awaitable.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/json.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace asio = webcpp::asio;
namespace crypto = webcpp::crypto;
namespace p256 = webcpp::crypto::curves::p256;
namespace data = webcpp::test::p256;
namespace test = webcpp::test;
namespace json = boost::json;

namespace {

using keypair = p256::basic_keypair<crypto::backends::bearssl>;
using public_key = p256::basic_public_key<crypto::backends::bearssl>;
using signature_type = std::array<std::uint8_t, p256::signature_size>;

// The number of cases of each Wycheproof file run through the asynchronous functions.
constexpr int wycheproof_cases = 50;

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

// The synchronous answers' digest: SHA-256 of the message, as WebCrypto's ECDSA hashes it.
std::array<std::uint8_t, p256::digest_size> sha256(std::span<std::uint8_t const> message) {
    std::array<std::uint8_t, p256::digest_size> out{};
    BOOST_TEST(webcpp::hash::digest_of<webcpp::hash::digests::sha2_256>(out, message).has_value());
    return out;
}

/** Whether every byte of `bytes` is zero. */
template <class Bytes>
bool all_zero(Bytes const& bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

// async_make's key pair, or nothing.
std::optional<keypair> made_async(asio::io_context& context, std::span<std::uint8_t const> scalar) {
    auto made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_make<keypair>(executor, scalar, std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!made.code);
    if (made.code || !made.value.has_value()) {
        return std::nullopt;
    }
    return std::move(std::get<0>(*made.value));
}

completed<signature_type> sign_async(asio::io_context& context, keypair const& key,
                                     std::span<std::uint8_t const> message) {
    return complete<signature_type>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_sign(executor, key, message, std::forward<decltype(token)>(token));
    });
}

boost::system::error_code verify_async(asio::io_context& context, public_key const& key,
                                       std::span<std::uint8_t const> message,
                                       std::span<std::uint8_t const> signature) {
    return complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, key, message, signature,
                                    std::forward<decltype(token)>(token));
    });
}

completed<crypto::secret<32>> agree_async(asio::io_context& context, keypair const& key,
                                          public_key const& peer) {
    return complete<crypto::secret<32>>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_agree(executor, key, peer, std::forward<decltype(token)>(token));
    });
}

void async_rfc6979(asio::io_context& context) {
    auto const key = made_async(context, data::rfc6979_scalar);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const own = key->public_key();
    if (!BOOST_TEST(own.has_value())) {
        return;
    }
    BOOST_TEST(own->uncompressed() == data::rfc6979_public);
    for (auto const& [text, expected] :
         {std::pair{std::string_view("sample"), data::rfc6979_sample},
          std::pair{std::string_view("test"), data::rfc6979_test}}) {
        auto const message = bytes_of(text);
        auto const signed_async = sign_async(context, *key, message);
        BOOST_TEST(!signed_async.code);
        if (!BOOST_TEST(signed_async.value.has_value())) {
            continue;
        }
        auto const& signature = std::get<0>(*signed_async.value);
        BOOST_TEST(signature == expected);
        auto const signed_sync = key->sign_ecdsa(sha256(message));
        BOOST_TEST(signed_sync.has_value() && *signed_sync == signature);
        BOOST_TEST(!verify_async(context, *own, message, signature));
    }
}

json::value load(std::string const& name) {
    auto const text = test::read_file(WEBCPP_TEST_WYCHEPROOF "/testvectors_v1/" + name + ".json");
    boost::system::error_code ec;
    auto value = json::parse(text, ec);
    BOOST_TEST(!ec);
    return value;
}

std::string str(json::value const& v) {
    return std::string(std::string_view(v.as_string()));
}

void async_wycheproof_ecdsa(asio::io_context& context) {
    auto const doc = load("ecdsa_secp256r1_sha256_p1363_test");
    int run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        auto const key =
            public_key::make(test::from_hex(str(group.at("publicKey").at("uncompressed"))));
        if (!BOOST_TEST(key.has_value())) {
            continue;
        }
        for (auto const& t : group.at("tests").as_array()) {
            if (run == wycheproof_cases) {
                break;
            }
            if (str(t.at("result")) != "valid") {
                continue;
            }
            ++run;
            auto message = test::from_hex(str(t.at("msg")));
            auto const encoded = test::from_hex(str(t.at("sig")));
            if (!BOOST_TEST_EQ(encoded.size(), p256::signature_size)) {
                continue;
            }
            std::span<std::uint8_t const, p256::signature_size> const signature(encoded.data(),
                                                                                encoded.size());
            auto const verified_sync = p256::verify_ecdsa(signature, sha256(message), *key);
            BOOST_TEST(verified_sync.has_value());
            BOOST_TEST(!verify_async(context, *key, message, encoded));
            // A changed byte of the message: both refuse it.
            message.push_back(0);
            message.front() ^= 1U;
            BOOST_TEST(p256::verify_ecdsa(signature, sha256(message), *key).error() ==
                       crypto::error::invalid_signature);
            BOOST_TEST(verify_async(context, *key, message, encoded) ==
                       crypto::error::invalid_signature);
        }
    }
    BOOST_TEST_EQ(run, wycheproof_cases);
    std::cout << "ecdsa_secp256r1_sha256_p1363_test: async_verified=" << run << '\n';
}

// A case's private key as 32 bytes: Wycheproof writes it as an ASN.1 integer's bytes, which may
// carry a leading 00, or shorter; the leading zero bytes are stripped and the rest left-padded.
// More than 32 significant bytes is no P-256 scalar: nothing is returned.
std::optional<std::array<std::uint8_t, p256::secret_key_size>> scalar_bytes(
    std::vector<std::uint8_t> const& integer) {
    auto const first = std::ranges::find_if(integer, [](std::uint8_t b) { return b != 0; });
    auto const significant = static_cast<std::size_t>(integer.end() - first);
    if (significant > p256::secret_key_size) {
        return std::nullopt;
    }
    std::array<std::uint8_t, p256::secret_key_size> padded{};
    std::copy(first, integer.end(), padded.end() - static_cast<std::ptrdiff_t>(significant));
    return padded;
}

void async_wycheproof_ecdh(asio::io_context& context) {
    auto const doc = load("ecdh_secp256r1_ecpoint_test");
    int run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        for (auto const& t : group.at("tests").as_array()) {
            if (run == wycheproof_cases) {
                break;
            }
            if (str(t.at("result")) != "valid") {
                continue;
            }
            ++run;
            auto const scalar = scalar_bytes(test::from_hex(str(t.at("private"))));
            auto const peer = public_key::make(test::from_hex(str(t.at("public"))));
            auto const shared = test::from_hex(str(t.at("shared")));
            if (!BOOST_TEST(scalar.has_value()) || !BOOST_TEST(peer.has_value())) {
                continue;
            }
            auto const key = made_async(context, *scalar);
            auto const synchronous = keypair::make(*scalar);
            if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(synchronous.has_value())) {
                continue;
            }
            auto const agreed_sync = synchronous->ecdh_x(*peer);
            auto const agreed = agree_async(context, *key, *peer);
            BOOST_TEST(!agreed.code);
            if (!BOOST_TEST(agreed.value.has_value()) || !BOOST_TEST(agreed_sync.has_value())) {
                continue;
            }
            auto const bytes = std::get<0>(*agreed.value).bytes();
            BOOST_TEST(std::ranges::equal(bytes, shared));
            BOOST_TEST(std::ranges::equal(bytes, agreed_sync->bytes()));
        }
    }
    BOOST_TEST_EQ(run, wycheproof_cases);
    std::cout << "ecdh_secp256r1_ecpoint_test: async_agreed=" << run << '\n';
}

void async_verify_refused(asio::io_context& context) {
    auto const key = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const message = bytes_of("test");
    auto signature = data::rfc6979_test;
    BOOST_TEST(!verify_async(context, *key, message, signature));
    signature[10] ^= 1U;
    BOOST_TEST(verify_async(context, *key, message, signature) == crypto::error::invalid_signature);
    signature[10] ^= 1U;
    BOOST_TEST(verify_async(context, *key, message, std::span(signature).first(63)) ==
               crypto::error::invalid_signature);
    std::fill_n(signature.begin(), p256::coordinate_size, std::uint8_t{0});
    BOOST_TEST(verify_async(context, *key, message, signature) == crypto::error::invalid_signature);
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
    auto const own = key.public_key();
    if (!BOOST_TEST(own.has_value())) {
        return;
    }
    auto const signed_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key, message, std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!signed_async.code);
    if (!BOOST_TEST(signed_async.value.has_value())) {
        return;
    }
    auto const& signature = std::get<0>(*signed_async.value);
    BOOST_TEST(p256::verify_ecdsa(signature, sha256(message), *own).has_value());
    auto const verified = complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, *own, message, signature,
                                    std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!verified);
}

void async_generate(asio::io_context& context) {
    generated<p256::keypair>(context);
    generated<keypair>(context);
}

void async_make_refused(asio::io_context& context) {
    auto const peer = public_key::make(data::rfc6979_public);
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    auto const refused = [&](std::span<std::uint8_t const> scalar, crypto::error expected) {
        auto const made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_make<keypair>(executor, scalar,
                                               std::forward<decltype(token)>(token));
        });
        BOOST_TEST(made.code == expected);
        if (!BOOST_TEST(made.value.has_value())) {
            return;
        }
        auto const& empty = std::get<0>(*made.value);
        BOOST_TEST(empty.public_key().error() == crypto::error::invalid_state);
        BOOST_TEST(empty.secret_scalar().error() == crypto::error::invalid_state);
        BOOST_TEST(empty.sign_ecdsa(sha256(message)).error() == crypto::error::invalid_state);
        BOOST_TEST(empty.ecdh_x(*peer).error() == crypto::error::invalid_state);
        auto const signed_empty = sign_async(context, empty, message);
        BOOST_TEST(signed_empty.code == crypto::error::invalid_state);
        if (BOOST_TEST(signed_empty.value.has_value())) {
            BOOST_TEST(all_zero(std::get<0>(*signed_empty.value)));
        }
        auto const agreed_empty = agree_async(context, empty, *peer);
        BOOST_TEST(agreed_empty.code == crypto::error::invalid_state);
        if (BOOST_TEST(agreed_empty.value.has_value())) {
            BOOST_TEST(all_zero(std::get<0>(*agreed_empty.value).bytes()));
        }
    };
    refused(std::span(data::rfc6979_scalar).first(31), crypto::error::invalid_key_size);
    refused(data::order, crypto::error::invalid_secret_key);
}

void async_destroyed(asio::io_context& context) {
    signature_type signature{};
    boost::system::error_code sign_code;
    boost::system::error_code agree_code;
    std::array<std::uint8_t, 32> shared{};
    std::array<std::uint8_t, 32> expected_shared{};
    {
        auto key = std::make_unique<keypair>(*keypair::make(data::rfc6979_scalar));
        auto message = std::make_unique<std::vector<std::uint8_t>>(bytes_of("sample"));
        auto peer = std::make_unique<public_key>(*public_key::make(data::rfc6979_public));
        auto const agreed_sync = key->ecdh_x(*peer);
        if (!BOOST_TEST(agreed_sync.has_value())) {
            return;
        }
        std::ranges::copy(agreed_sync->bytes(), expected_shared.begin());
        crypto::async_sign(context.get_executor(), *key, *message,
                           [&](boost::system::error_code code, signature_type done) {
                               sign_code = code;
                               signature = done;
                           });
        crypto::async_agree(context.get_executor(), *key, *peer,
                            [&](boost::system::error_code code, crypto::secret<32> done) {
                                agree_code = code;
                                std::ranges::copy(done.bytes(), shared.begin());
                            });
        // Everything the calls read goes out of scope here, before the completions.
    }
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(!sign_code);
    BOOST_TEST(signature == data::rfc6979_sample);
    BOOST_TEST(!agree_code);
    BOOST_TEST(shared == expected_shared);
}

void async_coroutine(asio::io_context& context) {
    bool done = false;
    asio::co_spawn(
        context,
        [&]() -> asio::awaitable<void> {
            auto const executor = co_await asio::this_coro::executor;
            auto const message = bytes_of("test");
            auto made_result = co_await crypto::async_make<p256::keypair>(
                executor, data::rfc6979_scalar, asio::as_tuple(asio::use_awaitable));
            auto& [made_code, key] = made_result;
            BOOST_TEST(!made_code);
            auto [sign_code, signature] = co_await crypto::async_sign(
                executor, key, message, asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!sign_code);
            BOOST_TEST(signature == data::rfc6979_test);
            auto const own = key.public_key();
            if (!BOOST_TEST(own.has_value())) {
                co_return;
            }
            auto [verify_code] = co_await crypto::async_verify(executor, *own, message, signature,
                                                               asio::as_tuple(asio::use_awaitable));
            BOOST_TEST(!verify_code);
            auto generate_result = co_await crypto::async_generate<p256::keypair>(
                executor, asio::as_tuple(asio::use_awaitable));
            auto& [generate_code, peer_key] = generate_result;
            BOOST_TEST(!generate_code);
            auto const peer = peer_key.public_key();
            if (!BOOST_TEST(peer.has_value())) {
                co_return;
            }
            auto agree_result = co_await crypto::async_agree(executor, key, *peer,
                                                             asio::as_tuple(asio::use_awaitable));
            auto& [agree_code, shared] = agree_result;
            BOOST_TEST(!agree_code);
            auto const back = peer_key.ecdh_x(*own);
            BOOST_TEST(back.has_value() && std::ranges::equal(shared.bytes(), back->bytes()));
            done = true;
        },
        [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

}  // namespace

int main() {
    asio::io_context context;
    async_rfc6979(context);
    async_wycheproof_ecdsa(context);
    async_wycheproof_ecdh(context);
    async_verify_refused(context);
    async_generate(context);
    async_make_refused(context);
    async_destroyed(context);
    async_coroutine(context);
    return webcpp::test::exit_status(boost::report_errors());
}
