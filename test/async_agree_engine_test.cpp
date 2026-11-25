// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The free async_agree, one template over the key pair (crypto::agreement_keypair), on a backend
// that completes by itself, natively: a stand-in whose detail::asynchronous_backend_v is true and
// whose detail::async_engine answers agree, as the browser's backend does, with a secret of its
// own. X25519's and P-256's key pairs of the stand-in (the empty ones of an error completion, since
// no engine makes one, and P-256's peer an unwritten key) reach the engine's agree through the
// free function and the member alike, with the key pair and the peer the caller gave, and complete
// through the executor after the initiating call returned.

#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/async_access.hpp>
#include <webcpp/crypto/detail/p_curves.hpp>
#include <webcpp/crypto/keypair.hpp>
#include <webcpp/secure/secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
namespace asio = webcpp::asio;

namespace {

// A backend that completes by itself, as the browser's does.
struct stand_in_browser {};

// What the stand-in's engine saw: its calls, and the key pair and the peer of the last one.
struct engine_calls {
    int count = 0;
    void const* key_pair = nullptr;
    void const* peer_key = nullptr;
};

// The stand-in engine's record, which the test resets before each operation.
engine_calls& seen() {
    static engine_calls calls;
    return calls;
}

// The secret the stand-in's engine agrees, whatever its keys: 0x5a in every byte.
constexpr std::uint8_t agreed_byte = 0x5a;

}  // namespace

namespace webcpp::crypto::detail {

template <>
inline constexpr bool asynchronous_backend_v<stand_in_browser> = true;

// P-256's key pair resets its state when it is destroyed: the stand-in's state holds nothing.
template <>
struct p_curve_engine<families::p256, stand_in_browser> {
    using state = p_curve_state<families::p256, stand_in_browser>;

    static void reset(state& /*engine_state*/) noexcept {}
};

// The stand-in's engine: agree records its arguments and completes, through a post, with its
// secret.
template <>
struct async_engine<stand_in_browser> {
    template <class Executor, class Keypair, class PublicKey, class CompletionToken>
    static auto agree(Executor const& completion_executor, Keypair const& key_pair,
                      PublicKey const& peer_key, CompletionToken&& completion_token) {
        ++seen().count;
        seen().key_pair = &key_pair;
        seen().peer_key = &peer_key;
        return complete_by_post(completion_executor, completion_token,
                                []() noexcept -> boost::system::result<secure::secret<32>> {
                                    secure::secret<32> agreed;
                                    agreed.writable()[0] = agreed_byte;
                                    agreed.writable()[31] = agreed_byte;
                                    return agreed;
                                });
    }
};

}  // namespace webcpp::crypto::detail

namespace {

using x25519_keypair = crypto::curves::x25519::basic_keypair<stand_in_browser>;
using p256_keypair = crypto::curves::p256::basic_keypair<stand_in_browser>;
using p256_public_key = crypto::curves::p256::basic_public_key<stand_in_browser>;

static_assert(crypto::agreement_keypair<x25519_keypair>);
static_assert(crypto::agreement_keypair<p256_keypair>);

// Runs `start(executor, handler)`, then the context: one completion, after the initiating call
// returned, with the stand-in's secret, the engine reached once with the caller's key pair and
// peer.
template <class Keypair, class PublicKey, class Start>
void completes_through_engine(asio::io_context& context, Keypair const& key_pair,
                              PublicKey const& peer_key, Start start) {
    seen() = {};
    int completions = 0;
    bool returned = false;
    bool after_return = false;
    boost::system::error_code completion_code;
    std::array<std::uint8_t, 32> agreed_bytes{};
    start(context.get_executor(), [&](boost::system::error_code code, secure::secret<32> agreed) {
        ++completions;
        after_return = returned;
        completion_code = code;
        std::ranges::copy(agreed.bytes(), agreed_bytes.begin());
    });
    returned = true;
    BOOST_TEST_EQ(completions, 0);
    context.restart();
    context.run();  // lint-run: the test's event loop
    BOOST_TEST_EQ(completions, 1);
    BOOST_TEST(after_return);
    BOOST_TEST(!completion_code);
    BOOST_TEST_EQ(agreed_bytes[0], agreed_byte);
    BOOST_TEST_EQ(agreed_bytes[31], agreed_byte);
    BOOST_TEST_EQ(seen().count, 1);
    BOOST_TEST(seen().key_pair == &key_pair);
    BOOST_TEST(seen().peer_key == &peer_key);
}

// The free async_agree and the member, on X25519's key pair and on P-256's.
template <class Keypair, class PublicKey>
void agrees_through_engine(asio::io_context& context, Keypair const& key_pair,
                           PublicKey const& peer_key) {
    completes_through_engine(context, key_pair, peer_key, [&](auto const& executor, auto handler) {
        crypto::async_agree(executor, key_pair, peer_key, std::move(handler));
    });
    completes_through_engine(context, key_pair, peer_key, [&](auto const& executor, auto handler) {
        key_pair.async_agree(executor, peer_key, std::move(handler));
    });
}

}  // namespace

int main() {
    asio::io_context context;
    auto const x25519_pair = crypto::detail::async_access::empty<x25519_keypair>();
    auto const x25519_peer =
        crypto::curves::x25519::public_key::from_bytes(std::array<std::uint8_t, 32>{9});
    if (BOOST_TEST(x25519_peer.has_value())) {
        agrees_through_engine(context, x25519_pair, *x25519_peer);
    }
    auto const p256_pair = crypto::detail::async_access::empty<p256_keypair>();
    auto const p256_peer = crypto::detail::p_curve_access::blank<p256_public_key>();
    agrees_through_engine(context, p256_pair, p256_peer);
    return webcpp::test::exit_status(boost::report_errors());
}
