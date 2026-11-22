// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The contract every curve's key pair meets (design D8), the concept `crypto::keypair`: made from
 its secret bytes by `make` or drawn by `generate`, its typed public key, which goes straight into
 `crypto::verify`, its secret bytes back by `secret()`, and `sign(scheme, input)` for every scheme
 its curve declares, at least one.

 Each curve's header checks its own key pair with a `static_assert` where its default backend is
 linked.

 @see "Signatures: the scheme and the input", in the guide.
*/
#ifndef WEBCPP_CRYPTO_KEYPAIR_HPP
#define WEBCPP_CRYPTO_KEYPAIR_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/secret.hpp>
#include <webcpp/crypto/signing.hpp>

#include <boost/system/result.hpp>

#include <concepts>
#include <cstdint>
#include <span>

namespace webcpp::crypto {

namespace detail {

/**
 * Whether the key pair `Keypair` keeps its curve's word about `Scheme`: a scheme the curve does
 * not declare for it asks nothing; one it declares (`signs_with_v`) asks that
 * `key.sign(scheme, message)` be a valid call.
 *
 * @tparam Keypair A key pair's type.
 * @tparam Scheme A scheme tag.
 */
template <class Keypair, class Scheme>
concept signs_as_declared =
    !signs_with_v<Keypair, Scheme> ||
    requires(Keypair const& key, Scheme const& scheme, std::span<std::uint8_t const> message) {
        key.sign(scheme, message);
    };

/**
 * Whether the curve of `Keypair` declares at least one scheme for it.
 *
 * @tparam Keypair A key pair's type.
 */
template <class Keypair>
inline constexpr bool signs_some_scheme_v =
    signs_with_v<Keypair, eddsa_t> || signs_with_v<Keypair, ecdsa_sha256_t> ||
    signs_with_v<Keypair, ecdsa_sha256_recoverable_t> || signs_with_v<Keypair, schnorr_t>;

}  // namespace detail

/**
 * Whether `Keypair` is a key pair of the library's contract (design D8):
 * - `Keypair::make(secret_bytes)` and `Keypair::generate()` give `result<Keypair>`;
 * - `key.public_key()` gives `result<typename Keypair::public_key_type>`, the curve's typed
 *   public key, which `crypto::verify` takes;
 * - `key.secret()` gives `result<secret<Keypair::secret_key_size>>`, the bytes `make` takes back;
 * - `key.sign(scheme, message)` is valid for every scheme its curve declares for it
 *   (`detail::signs_with_v`), and it declares at least one.
 *
 * @tparam Keypair A type, without its reference and qualifiers.
 */
template <class Keypair>
concept keypair = detail::signs_some_scheme_v<Keypair> &&
                  requires(Keypair const& key, std::span<std::uint8_t const> secret_bytes) {
                      typename Keypair::public_key_type;
                      {
                          Keypair::make(secret_bytes)
                      } -> std::same_as<boost::system::result<Keypair>>;
                      { Keypair::generate() } -> std::same_as<boost::system::result<Keypair>>;
                      {
                          key.public_key()
                      } -> std::same_as<boost::system::result<typename Keypair::public_key_type>>;
                      {
                          key.secret()
                      } -> std::same_as<boost::system::result<secret<Keypair::secret_key_size>>>;
                  } && detail::signs_as_declared<Keypair, eddsa_t> &&
                  detail::signs_as_declared<Keypair, ecdsa_sha256_t> &&
                  detail::signs_as_declared<Keypair, ecdsa_sha256_recoverable_t> &&
                  detail::signs_as_declared<Keypair, schnorr_t>;

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_KEYPAIR_HPP
