// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// P-256's asynchronous functions on BearSSL, on a callback and in a coroutine. async_sign and
// async_verify take the scheme, crypto::ecdsa_sha256, and the synchronous calls' inputs: the
// message, which they hash with SHA-256, as WebCrypto's ECDSA with SHA-256 does, or
// crypto::prehashed{digest}; the synchronous answers they are checked against are
// sign(ecdsa_sha256, prehashed{digest}) and crypto::verify(ecdsa_sha256, signature,
// prehashed{digest}, key) of its digest, computed here.
// - async_rfc6979: RFC 6979 section A.2.5's key through async_from_secret, its messages "sample"
//   and "test" through async_sign give the RFC's signatures in their low-S form ("sample"'s S is
//   high in the RFC) and the synchronous ones, and async_verify accepts them, and the RFC's high-S
//   "sample" too; each completion arrives after the initiating call returned.
// - async_wycheproof_ecdsa: the first 50 valid cases of Wycheproof's ECDSA P-256 SHA-256 file in
//   WebCrypto's form (IEEE P1363's r || s) verify through async_verify as through crypto::verify;
//   with a changed byte of the message both refuse them with invalid_signature.
// - async_wycheproof_ecdh: the first 50 valid cases of Wycheproof's ECDH P-256 file on points
//   through async_from_secret and async_agree give the file's shared x and agree's.
// - async_prehashed: async_sign of a message equals key.sign(ecdsa_sha256, message), and of
//   prehashed{SHA-256 of the message} the same signature; async_verify of that marker completes
//   without error, and of a changed digest with invalid_signature. A key pair of a backend that
//   completes by itself (a stand-in whose detail::asynchronous_backend_v is true) signs a message
//   and no digest, checked by crypto::can_sign without instantiating the key pair's class.
// - async_verify_refused: a changed byte of the signature, a signature of 63 bytes and one whose
//   r is 0 complete with invalid_signature.
// - async_generate: async_generate gives a key pair whose signature verifies, on the default
//   backend and on BearSSL named.
// - async_from_secret_refused: a scalar of 31 bytes completes with invalid_key_size, the group
//   order with invalid_secret_key, each with an empty key pair, which refuses every member with
//   invalid_state (review focus 5), async_sign and async_agree on it too, with zeros.
// - async_destroyed: the key pair, the message and the peer's key destroyed after the initiating
//   call returns and before the completion: a synchronous backend has read them already, so the
//   completion gives the right result.
// - async_coroutine: the same in one coroutine of the context.
// - async_four_forms: each operation in its four forms (design D9), the member and the free,
//   synchronous and asynchronous, gives the same result: from_secret (the same public key),
//   generate (a key pair whose signature verifies), sign of a message and of prehashed{digest} (the
//   same signature, RFC 6979's), verify (each accepts the signature and refuses a changed one with
//   invalid_signature; each takes the signature as a std::vector, or 63 or 65 bytes,
//   invalid_signature), agree (the same secret); and the refusals are the same, a short scalar's
//   invalid_key_size and an empty key pair's invalid_state, each asynchronous completion arriving
//   after the initiating call returned.
// - async_member_deferred: key.async_sign with asio::deferred, of a crypto::prehashed{digest}
//   made in the call's argument list, launched after the statement that made it ended, runs when
//   launched and gives RFC 6979's signature.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/factories.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/hash/digest.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/hex.hpp"
#include "support/p256_data.hpp"
#include "support/test_data.hpp"

#include <webcpp/asio/as_tuple.hpp>
#include <webcpp/asio/awaitable.hpp>
#include <webcpp/asio/co_spawn.hpp>
#include <webcpp/asio/deferred.hpp>
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

// A backend that completes by itself, as part B's browser backend will: it is only named, never
// defined, and no key pair of it is made.
struct stand_in_async_backend;

namespace webcpp::crypto::detail {

template <>
inline constexpr bool asynchronous_backend_v<stand_in_async_backend> = true;

}  // namespace webcpp::crypto::detail

// Such a backend signs a message and no digest (WebCrypto has no prehash mode); the concept answers
// from the traits' partial specializations, without instantiating the key pair's class.
static_assert(!crypto::can_sign<p256::basic_keypair<stand_in_async_backend>, crypto::ecdsa_sha256_t,
                                crypto::prehashed<32>>);
static_assert(crypto::can_sign<p256::basic_keypair<stand_in_async_backend>, crypto::ecdsa_sha256_t,
                               std::span<std::uint8_t const>>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, crypto::prehashed<32>,
                                  p256::basic_public_key<stand_in_async_backend>>);
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, std::span<std::uint8_t const>,
                                 p256::basic_public_key<stand_in_async_backend>>);

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

// async_from_secret's key pair, or nothing.
std::optional<keypair> made_async(asio::io_context& context, std::span<std::uint8_t const> scalar) {
    auto made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_secret<keypair>(executor, scalar,
                                                  std::forward<decltype(token)>(token));
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
        return crypto::async_sign(executor, key, crypto::ecdsa_sha256, message,
                                  std::forward<decltype(token)>(token));
    });
}

boost::system::error_code verify_async(asio::io_context& context, public_key const& key,
                                       std::span<std::uint8_t const> message,
                                       std::span<std::uint8_t const> signature) {
    return complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, crypto::ecdsa_sha256, signature, message, key,
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
    for (auto const& [text, expected] : {
             std::pair{std::string_view("sample"), data::rfc6979_sample_low_s},
             std::pair{std::string_view("test"), data::rfc6979_test},
         }) {
        auto const message = bytes_of(text);
        auto const signed_async = sign_async(context, *key, message);
        BOOST_TEST(!signed_async.code);
        if (!BOOST_TEST(signed_async.value.has_value())) {
            continue;
        }
        auto const& signature = std::get<0>(*signed_async.value);
        BOOST_TEST(signature == expected);
        auto const signed_sync =
            key->sign(crypto::ecdsa_sha256, crypto::prehashed{sha256(message)});
        BOOST_TEST(signed_sync.has_value() && *signed_sync == signature);
        BOOST_TEST(!verify_async(context, *own, message, signature));
    }
    // The RFC's own "sample" signature, whose S is high: accepted too.
    BOOST_TEST(!verify_async(context, *own, bytes_of("sample"), data::rfc6979_sample));
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

// One valid case: the synchronous and the asynchronous verification accept it, and both refuse
// the message with a changed byte.
void check_wycheproof_ecdsa_case(asio::io_context& context, public_key const& key,
                                 json::value const& t) {
    auto message = test::from_hex(str(t.at("msg")));
    auto const encoded = test::from_hex(str(t.at("sig")));
    if (!BOOST_TEST_EQ(encoded.size(), p256::signature_size)) {
        return;
    }
    std::span<std::uint8_t const, p256::signature_size> const signature(encoded.data(),
                                                                        encoded.size());
    auto const verified_sync =
        crypto::verify(crypto::ecdsa_sha256, signature, crypto::prehashed{sha256(message)}, key);
    BOOST_TEST(verified_sync.has_value());
    BOOST_TEST(!verify_async(context, key, message, encoded));
    // A changed byte of the message: both refuse it.
    message.push_back(0);
    message.front() ^= 1U;
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, signature, crypto::prehashed{sha256(message)}, key)
            .error() == crypto::error::invalid_signature);
    BOOST_TEST(verify_async(context, key, message, encoded) == crypto::error::invalid_signature);
}

void async_wycheproof_ecdsa_group(asio::io_context& context, json::value const& group, int& run) {
    auto const key =
        public_key::from_bytes(test::from_hex(str(group.at("publicKey").at("uncompressed"))));
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    for (auto const& t : group.at("tests").as_array()) {
        if (run == wycheproof_cases) {
            break;
        }
        if (str(t.at("result")) != "valid") {
            continue;
        }
        ++run;
        check_wycheproof_ecdsa_case(context, *key, t);
    }
}

void async_wycheproof_ecdsa(asio::io_context& context) {
    auto const doc = load("ecdsa_secp256r1_sha256_p1363_test");
    int run = 0;
    for (auto const& group : doc.at("testGroups").as_array()) {
        // The groups after the 50th case are not read: their keys are not made.
        if (run == wycheproof_cases) {
            break;
        }
        async_wycheproof_ecdsa_group(context, group, run);
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

// One valid case: the key made asynchronously agrees with the peer's key as the vector says and
// as the synchronous key does.
void check_wycheproof_ecdh_case(asio::io_context& context, json::value const& t) {
    auto const scalar = scalar_bytes(test::from_hex(str(t.at("private"))));
    auto const peer = public_key::from_bytes(test::from_hex(str(t.at("public"))));
    auto const shared = test::from_hex(str(t.at("shared")));
    if (!BOOST_TEST(scalar.has_value()) || !BOOST_TEST(peer.has_value())) {
        return;
    }
    auto const key = made_async(context, *scalar);
    auto const synchronous = keypair::from_secret(*scalar);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(synchronous.has_value())) {
        return;
    }
    auto const agreed_sync = synchronous->agree(*peer);
    auto const agreed = agree_async(context, *key, *peer);
    BOOST_TEST(!agreed.code);
    if (!BOOST_TEST(agreed.value.has_value()) || !BOOST_TEST(agreed_sync.has_value())) {
        return;
    }
    auto const bytes = std::get<0>(*agreed.value).bytes();
    BOOST_TEST(std::ranges::equal(bytes, shared));
    BOOST_TEST(std::ranges::equal(bytes, agreed_sync->bytes()));
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
            check_wycheproof_ecdh_case(context, t);
        }
    }
    BOOST_TEST_EQ(run, wycheproof_cases);
    std::cout << "ecdh_secp256r1_ecpoint_test: async_agreed=" << run << '\n';
}

void async_prehashed(asio::io_context& context) {
    auto const key = keypair::from_secret(data::rfc6979_scalar);
    auto const own = public_key::from_bytes(data::rfc6979_public);
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(own.has_value())) {
        return;
    }
    auto const message = bytes_of("sample");
    auto digest = sha256(message);
    auto const signed_sync = key->sign(crypto::ecdsa_sha256, message);
    auto const signed_message = sign_async(context, *key, message);
    auto const signed_digest = complete<signature_type>(context, [&](auto const& executor,
                                                                     auto&& token) {
        return crypto::async_sign(executor, *key, crypto::ecdsa_sha256, crypto::prehashed{digest},
                                  std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!signed_message.code);
    BOOST_TEST(!signed_digest.code);
    if (!BOOST_TEST(signed_sync.has_value()) || !BOOST_TEST(signed_message.value.has_value()) ||
        !BOOST_TEST(signed_digest.value.has_value())) {
        return;
    }
    auto const& signature = std::get<0>(*signed_message.value);
    BOOST_TEST(signature == *signed_sync);
    BOOST_TEST(std::get<0>(*signed_digest.value) == *signed_sync);
    auto const verify_digest = [&] {
        return complete_code(context, [&](auto const& executor, auto&& token) {
            return crypto::async_verify(executor, crypto::ecdsa_sha256, signature,
                                        crypto::prehashed{digest}, *own,
                                        std::forward<decltype(token)>(token));
        });
    };
    BOOST_TEST(!verify_digest());
    digest[0] ^= 1U;
    BOOST_TEST(verify_digest() == crypto::error::invalid_signature);
}

void async_verify_refused(asio::io_context& context) {
    auto const key = public_key::from_bytes(data::rfc6979_public);
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
            return crypto::async_sign(executor, key, crypto::ecdsa_sha256, message,
                                      std::forward<decltype(token)>(token));
        });
    BOOST_TEST(!signed_async.code);
    if (!BOOST_TEST(signed_async.value.has_value())) {
        return;
    }
    auto const& signature = std::get<0>(*signed_async.value);
    BOOST_TEST(
        crypto::verify(crypto::ecdsa_sha256, signature, crypto::prehashed{sha256(message)}, *own)
            .has_value());
    auto const verified = complete_code(context, [&](auto const& executor, auto&& token) {
        return crypto::async_verify(executor, crypto::ecdsa_sha256, signature, message, *own,
                                    std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!verified);
}

void async_generate(asio::io_context& context) {
    generated<p256::keypair>(context);
    generated<keypair>(context);
}

// A key made from a refused scalar is the empty object a move leaves: every member says
// invalid_state, and the asynchronous functions complete with it and a zeroed value.
void check_empty_keypair(asio::io_context& context, keypair const& empty, public_key const& peer,
                         std::span<std::uint8_t const> message) {
    BOOST_TEST(empty.public_key().error() == crypto::error::invalid_state);
    BOOST_TEST(empty.secret().error() == crypto::error::invalid_state);
    BOOST_TEST(empty.sign(crypto::ecdsa_sha256, message).error() == crypto::error::invalid_state);
    BOOST_TEST(empty.agree(peer).error() == crypto::error::invalid_state);
    auto const signed_empty = sign_async(context, empty, message);
    BOOST_TEST(signed_empty.code == crypto::error::invalid_state);
    if (BOOST_TEST(signed_empty.value.has_value())) {
        BOOST_TEST(all_zero(std::get<0>(*signed_empty.value)));
    }
    auto const agreed_empty = agree_async(context, empty, peer);
    BOOST_TEST(agreed_empty.code == crypto::error::invalid_state);
    if (BOOST_TEST(agreed_empty.value.has_value())) {
        BOOST_TEST(all_zero(std::get<0>(*agreed_empty.value).bytes()));
    }
}

void check_from_secret_refused(asio::io_context& context, public_key const& peer,
                               std::span<std::uint8_t const> message,
                               std::span<std::uint8_t const> scalar, crypto::error expected) {
    auto const made = complete<keypair>(context, [&](auto const& executor, auto&& token) {
        return crypto::async_from_secret<keypair>(executor, scalar,
                                                  std::forward<decltype(token)>(token));
    });
    BOOST_TEST(made.code == expected);
    if (!BOOST_TEST(made.value.has_value())) {
        return;
    }
    check_empty_keypair(context, std::get<0>(*made.value), peer, message);
}

void async_from_secret_refused(asio::io_context& context) {
    auto const peer = public_key::from_bytes(data::rfc6979_public);
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    check_from_secret_refused(context, *peer, message, std::span(data::rfc6979_scalar).first(31),
                              crypto::error::invalid_key_size);
    check_from_secret_refused(context, *peer, message, data::order,
                              crypto::error::invalid_secret_key);
}

void async_destroyed(asio::io_context& context) {
    signature_type signature{};
    boost::system::error_code sign_code;
    boost::system::error_code agree_code;
    std::array<std::uint8_t, 32> shared{};
    std::array<std::uint8_t, 32> expected_shared{};
    {
        auto key = std::make_unique<keypair>(*keypair::from_secret(data::rfc6979_scalar));
        auto const message = std::make_unique<std::vector<std::uint8_t>>(bytes_of("sample"));
        auto const peer =
            std::make_unique<public_key>(*public_key::from_bytes(data::rfc6979_public));
        auto const agreed_sync = key->agree(*peer);
        if (!BOOST_TEST(agreed_sync.has_value())) {
            return;
        }
        std::ranges::copy(agreed_sync->bytes(), expected_shared.begin());
        crypto::async_sign(context.get_executor(), *key, crypto::ecdsa_sha256, *message,
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
    BOOST_TEST(signature == data::rfc6979_sample_low_s);
    BOOST_TEST(!agree_code);
    BOOST_TEST(shared == expected_shared);
}

// The second half of the coroutine: a generated key agrees with the first one's.
asio::awaitable<void> coroutine_agreement(asio::any_io_executor const& executor,
                                          p256::keypair const& key, public_key const& own,
                                          bool& done) {
    auto generate_result = co_await crypto::async_generate<p256::keypair>(
        executor, asio::as_tuple(asio::use_awaitable));
    auto& [generate_code, peer_key] = generate_result;
    BOOST_TEST(!generate_code);
    auto const peer = peer_key.public_key();
    if (!BOOST_TEST(peer.has_value())) {
        co_return;
    }
    auto agree_result =
        co_await crypto::async_agree(executor, key, *peer, asio::as_tuple(asio::use_awaitable));
    auto& [agree_code, shared] = agree_result;
    BOOST_TEST(!agree_code);
    auto const back = peer_key.agree(own);
    BOOST_TEST(back.has_value() && std::ranges::equal(shared.bytes(), back->bytes()));
    done = true;
}

asio::awaitable<void> coroutine_body(bool& done) {
    auto const executor = co_await asio::this_coro::executor;
    auto const message = bytes_of("test");
    auto made_result = co_await crypto::async_from_secret<p256::keypair>(
        executor, data::rfc6979_scalar, asio::as_tuple(asio::use_awaitable));
    auto& [made_code, key] = made_result;
    BOOST_TEST(!made_code);
    auto [sign_code, signature] = co_await crypto::async_sign(
        executor, key, crypto::ecdsa_sha256, message, asio::as_tuple(asio::use_awaitable));
    BOOST_TEST(!sign_code);
    BOOST_TEST(signature == data::rfc6979_test);
    auto const own = key.public_key();
    if (!BOOST_TEST(own.has_value())) {
        co_return;
    }
    auto [verify_code] =
        co_await crypto::async_verify(executor, crypto::ecdsa_sha256, signature, message, *own,
                                      asio::as_tuple(asio::use_awaitable));
    BOOST_TEST(!verify_code);
    co_await coroutine_agreement(executor, key, *own, done);
}

void async_coroutine(asio::io_context& context) {
    bool done = false;
    asio::co_spawn(context, coroutine_body(done),
                   [](std::exception_ptr const& failure) { BOOST_TEST(!failure); });
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST(done);
}

// from_secret in its four forms: the same key pair, and the same refusal of a short scalar.
void four_forms_from_secret(asio::io_context& context) {
    auto const expected = keypair::from_secret(data::rfc6979_scalar);
    auto const free_sync = crypto::from_secret<keypair>(data::rfc6979_scalar);
    auto const member_async = complete<keypair>(context, [](auto const& executor, auto&& token) {
        return keypair::async_from_secret(executor, data::rfc6979_scalar,
                                          std::forward<decltype(token)>(token));
    });
    auto const free_async = complete<keypair>(context, [](auto const& executor, auto&& token) {
        return crypto::async_from_secret<keypair>(executor, data::rfc6979_scalar,
                                                  std::forward<decltype(token)>(token));
    });
    BOOST_TEST(!member_async.code);
    BOOST_TEST(!free_async.code);
    if (!BOOST_TEST(expected.has_value()) || !BOOST_TEST(free_sync.has_value()) ||
        !BOOST_TEST(member_async.value.has_value()) || !BOOST_TEST(free_async.value.has_value())) {
        return;
    }
    auto const public_of = [](keypair const& key) { return key.public_key()->uncompressed(); };
    BOOST_TEST(public_of(*expected) == data::rfc6979_public);
    BOOST_TEST(public_of(*free_sync) == data::rfc6979_public);
    BOOST_TEST(public_of(std::get<0>(*member_async.value)) == data::rfc6979_public);
    BOOST_TEST(public_of(std::get<0>(*free_async.value)) == data::rfc6979_public);
    auto const short_scalar = std::span(data::rfc6979_scalar).first(31);
    BOOST_TEST(keypair::from_secret(short_scalar).error() == crypto::error::invalid_key_size);
    BOOST_TEST(crypto::from_secret<keypair>(short_scalar).error() ==
               crypto::error::invalid_key_size);
    BOOST_TEST(complete<keypair>(context, [&](auto const& executor, auto&& token) {
                   return keypair::async_from_secret(executor, short_scalar,
                                                     std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
    BOOST_TEST(complete<keypair>(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_from_secret<keypair>(executor, short_scalar,
                                                             std::forward<decltype(token)>(token));
               }).code == crypto::error::invalid_key_size);
}

// Whether a generated key pair signs a message its own public key verifies.
bool signs_and_verifies(keypair const& key) {
    std::array<std::uint8_t, 3> const message{1, 2, 3};
    auto const signature = key.sign(crypto::ecdsa_sha256, message);
    auto const own = key.public_key();
    return signature.has_value() && own.has_value() &&
           own->verify(crypto::ecdsa_sha256, *signature, message).has_value();
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

// sign in its four forms, of `input`: the same signature, or the same refusal and zeros.
template <class Input>
void check_four_signatures(asio::io_context& context, keypair const& key, Input const& input,
                           boost::system::error_code expected_code) {
    auto const member_sync = key.sign(crypto::ecdsa_sha256, input);
    auto const free_sync = crypto::sign(key, crypto::ecdsa_sha256, input);
    auto const member_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return key.async_sign(executor, crypto::ecdsa_sha256, input,
                                  std::forward<decltype(token)>(token));
        });
    auto const free_async =
        complete<signature_type>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_sign(executor, key, crypto::ecdsa_sha256, input,
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
        BOOST_TEST(all_zero(std::get<0>(*member_async.value)));
        BOOST_TEST(all_zero(std::get<0>(*free_async.value)));
        return;
    }
    if (!BOOST_TEST(member_sync.has_value()) || !BOOST_TEST(free_sync.has_value())) {
        return;
    }
    BOOST_TEST(*member_sync == data::rfc6979_test);
    BOOST_TEST(*free_sync == *member_sync);
    BOOST_TEST(std::get<0>(*member_async.value) == *member_sync);
    BOOST_TEST(std::get<0>(*free_async.value) == *member_sync);
}

// verify in its four forms, of `input`: the same answer, the signature given to each as it is
// given here (an array, a std::vector or a span).
template <class Signature, class Input>
void check_four_verifications(asio::io_context& context, public_key const& key,
                              Signature const& signature, Input const& input,
                              boost::system::error_code expected_code) {
    auto const code_of = [](boost::system::result<void> const& done) {
        return done ? boost::system::error_code{} : done.error();
    };
    BOOST_TEST(code_of(key.verify(crypto::ecdsa_sha256, signature, input)) == expected_code);
    BOOST_TEST(code_of(crypto::verify(crypto::ecdsa_sha256, signature, input, key)) ==
               expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return key.async_verify(executor, crypto::ecdsa_sha256, signature, input,
                                           std::forward<decltype(token)>(token));
               }) == expected_code);
    BOOST_TEST(complete_code(context, [&](auto const& executor, auto&& token) {
                   return crypto::async_verify(executor, crypto::ecdsa_sha256, signature, input,
                                               key, std::forward<decltype(token)>(token));
               }) == expected_code);
}

// agree in its four forms: the same secret, or the same refusal and zeros.
void check_four_agreements(asio::io_context& context, keypair const& key, public_key const& peer,
                           boost::system::error_code expected_code) {
    auto const member_sync = key.agree(peer);
    auto const free_sync = crypto::agree(key, peer);
    auto const member_async =
        complete<crypto::secret<32>>(context, [&](auto const& executor, auto&& token) {
            return key.async_agree(executor, peer, std::forward<decltype(token)>(token));
        });
    auto const free_async =
        complete<crypto::secret<32>>(context, [&](auto const& executor, auto&& token) {
            return crypto::async_agree(executor, key, peer, std::forward<decltype(token)>(token));
        });
    BOOST_TEST(member_async.code == expected_code);
    BOOST_TEST(free_async.code == expected_code);
    if (!BOOST_TEST(member_async.value.has_value()) || !BOOST_TEST(free_async.value.has_value())) {
        return;
    }
    auto const member_bytes = std::get<0>(*member_async.value).bytes();
    auto const free_bytes = std::get<0>(*free_async.value).bytes();
    if (expected_code) {
        BOOST_TEST(member_sync.error() == expected_code);
        BOOST_TEST(free_sync.error() == expected_code);
        BOOST_TEST(all_zero(member_bytes));
        BOOST_TEST(all_zero(free_bytes));
        return;
    }
    if (!BOOST_TEST(member_sync.has_value()) || !BOOST_TEST(free_sync.has_value())) {
        return;
    }
    BOOST_TEST(std::ranges::equal(free_sync->bytes(), member_sync->bytes()));
    BOOST_TEST(std::ranges::equal(member_bytes, member_sync->bytes()));
    BOOST_TEST(std::ranges::equal(free_bytes, member_sync->bytes()));
}

void async_member_deferred(asio::io_context& context) {
    auto const key = keypair::from_secret(data::rfc6979_scalar);
    if (!BOOST_TEST(key.has_value())) {
        return;
    }
    auto const digest = sha256(bytes_of("test"));
    // The marker is a temporary of this statement: the operation keeps its own copy.
    auto operation = key->async_sign(context.get_executor(), crypto::ecdsa_sha256,
                                     crypto::prehashed{digest}, asio::deferred);
    int calls = 0;
    signature_type signature{};
    std::move(operation)([&](boost::system::error_code code, signature_type done) {
        ++calls;
        BOOST_TEST(!code);
        signature = done;
    });
    BOOST_TEST_EQ(calls, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(calls, 1);
    BOOST_TEST(signature == data::rfc6979_test);
}

void async_four_forms(asio::io_context& context) {
    four_forms_from_secret(context);
    four_forms_generate(context);
    auto key = keypair::from_secret(data::rfc6979_scalar);
    auto const own = public_key::from_bytes(data::rfc6979_public);
    auto const peer_key = keypair::generate();
    if (!BOOST_TEST(key.has_value()) || !BOOST_TEST(own.has_value()) ||
        !BOOST_TEST(peer_key.has_value())) {
        return;
    }
    auto const peer = peer_key->public_key();
    if (!BOOST_TEST(peer.has_value())) {
        return;
    }
    auto const message = bytes_of("test");
    auto digest = sha256(message);
    check_four_signatures(context, *key, message, {});
    check_four_signatures(context, *key, crypto::prehashed{digest}, {});
    check_four_verifications(context, *own, data::rfc6979_test, message, {});
    check_four_verifications(context, *own, data::rfc6979_test, crypto::prehashed{digest}, {});
    std::vector<std::uint8_t> const received(data::rfc6979_test.begin(), data::rfc6979_test.end());
    check_four_verifications(context, *own, received, message, {});
    auto longer = received;
    longer.push_back(0);
    check_four_verifications(context, *own, longer, message, crypto::error::invalid_signature);
    check_four_verifications(context, *own, std::span<std::uint8_t const>(received).first(63),
                             message, crypto::error::invalid_signature);
    auto changed = data::rfc6979_test;
    changed[10] ^= 1U;
    check_four_verifications(context, *own, changed, message, crypto::error::invalid_signature);
    digest[0] ^= 1U;
    check_four_verifications(context, *own, data::rfc6979_test, crypto::prehashed{digest},
                             crypto::error::invalid_signature);
    check_four_agreements(context, *key, *peer, {});
    [[maybe_unused]] keypair const taken(std::move(*key));
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the empty key pair
    check_four_signatures(context, *key, message, crypto::error::invalid_state);
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the empty key pair
    check_four_agreements(context, *key, *peer, crypto::error::invalid_state);
}

}  // namespace

int main() {
    asio::io_context context;
    async_rfc6979(context);
    async_wycheproof_ecdsa(context);
    async_wycheproof_ecdh(context);
    async_prehashed(context);
    async_verify_refused(context);
    async_generate(context);
    async_from_secret_refused(context);
    async_destroyed(context);
    async_coroutine(context);
    async_four_forms(context);
    async_member_deferred(context);
    return webcpp::test::exit_status(boost::report_errors());
}
