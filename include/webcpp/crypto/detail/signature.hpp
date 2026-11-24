// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The one class template of every signature type (design D1), `detail::basic_signature<Tag, Size>`,
 which each curve's header names by a tag of its own, so that no two types convert into each
 other; and the trait `detail::signature_of<Key, Scheme>`, which each curve's header specialises
 to name the signature type of its keys under each scheme they sign or verify.
*/
#ifndef WEBCPP_CRYPTO_DETAIL_SIGNATURE_HPP
#define WEBCPP_CRYPTO_DETAIL_SIGNATURE_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

struct signature_access;

/**
 * A signature of one curve and scheme: its bytes, of a fixed size, as the scheme writes them.
 *
 * Each curve's header names it by a tag of its own (`curves::p256::ecdsa_signature`, ...), so
 * that a signature of one curve or scheme is never taken for another's: no two of these types,
 * nor a type and bytes, convert into each other. It is a regular value type, public, copied
 * freely and compared with `==`; its default value is all zeros, which no verification accepts.
 * It is made from bytes by `from_bytes` (or `crypto::from_bytes<T>`), which checks the size
 * alone, and by the `sign` of its curve and scheme.
 *
 * @tparam Tag The type's tag, an empty struct with `static constexpr bool recoverable`, true
 * for a signature whose last byte is a recovery id.
 * @tparam Size The signature's size in bytes.
 */
template <class Tag, std::size_t Size>
class basic_signature {
public:
    /** The size of the signature, in bytes. */
    static constexpr std::size_t size = Size;

    /** Makes the signature of all zeros, which no verification accepts. */
    basic_signature() noexcept = default;

    /**
     * Makes a signature from its bytes, as a peer sends them. The size alone is checked (design
     * R2): whether the values it holds are in range is verification's judgment, so a signature
     * `verify` refuses may still be made, normalised and refused with its curve's policy.
     *
     * @param signature_bytes `size` bytes.
     * @return The signature; `invalid_signature` for another size.
     */
    [[nodiscard]] static boost::system::result<basic_signature> from_bytes(
        std::span<std::uint8_t const> signature_bytes) noexcept {
        if (signature_bytes.size() != Size) {
            return error::invalid_signature;
        }
        basic_signature made_signature;
        std::ranges::copy(signature_bytes, made_signature.signature_bytes_.begin());
        return made_signature;
    }

    /**
     * The signature's bytes, as its scheme writes them.
     *
     * @return `size` bytes.
     */
    [[nodiscard]] std::array<std::uint8_t, Size> const& bytes() const noexcept {
        return signature_bytes_;
    }

    /**
     * The recovery id, the signature's last byte as it is: 0 to 3 in a signature `sign` made, and
     * `recover` refuses a larger one. Only a recoverable signature has it.
     *
     * @return `bytes()[size - 1]`.
     */
    [[nodiscard]] std::uint8_t recovery_id() const noexcept
        requires Tag::recoverable
    {
        return signature_bytes_[Size - 1];
    }

    /**
     * Whether two signatures hold the same bytes; a signature is public, so the comparison need
     * not take a constant time.
     *
     * @return Whether every byte is equal.
     */
    [[nodiscard]] bool operator==(basic_signature const&) const noexcept = default;

private:
    friend struct signature_access;

    std::array<std::uint8_t, Size> signature_bytes_{};
};

/**
 * The library's way to make a signature from the bytes a backend wrote, whose size the type
 * fixes, so that nothing is checked at run time.
 */
struct signature_access {
    /**
     * Makes a signature of the type `Signature` from its bytes.
     *
     * @tparam Signature A `basic_signature`.
     * @param signature_bytes The bytes a backend wrote.
     * @return The signature.
     */
    template <class Signature>
    [[nodiscard]] static Signature of(
        std::array<std::uint8_t, Signature::size> const& signature_bytes) noexcept {
        Signature made_signature;
        made_signature.signature_bytes_ = signature_bytes;
        return made_signature;
    }
};

/**
 * The signature type of the key `Key` under the scheme `Scheme`: `void`, unless the key's curve
 * says otherwise, for each key pair that signs with the scheme and each public key that verifies
 * it (the traits `signs_with_v` and `verifies_with_v` of `<webcpp/crypto/signing.hpp>`).
 *
 * A curve's header specialises it: the header is included before the trait is used on its keys,
 * or the specialisation comes after the first use (ill-formed).
 *
 * @tparam Key A key pair's or a public key's type, without its reference and qualifiers.
 * @tparam Scheme A scheme tag.
 */
template <class Key, class Scheme>
struct signature_of {
    /** No signature: the key neither signs nor verifies the scheme. */
    using type = void;
};

/**
 * The signature type of the key `Key` under the scheme `Scheme`, `signature_of`'s.
 *
 * @tparam Key A key pair's or a public key's type, without its reference and qualifiers.
 * @tparam Scheme A scheme tag.
 */
template <class Key, class Scheme>
using signature_of_t = signature_of<Key, Scheme>::type;

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_SIGNATURE_HPP
