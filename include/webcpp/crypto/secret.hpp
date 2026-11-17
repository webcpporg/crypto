// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/** A secret output of webcpp::crypto, which wipes itself (design D9). */
#ifndef WEBCPP_CRYPTO_SECRET_HPP
#define WEBCPP_CRYPTO_SECRET_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/wipe.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto {

/**
 `N` secret bytes: a shared secret, a session key, a converted secret key.

 They are wiped by volatile stores when the object is destroyed or moved from; a copy is made
 only by `clone`.

 @tparam N The number of bytes.
*/
template <std::size_t N>
class secret {
public:
    /** The number of bytes. */
    static constexpr std::size_t size_bytes = N;

    /** Zero bytes. */
    secret() noexcept = default;

    /**
     Takes the bytes of `other`, which is wiped.

     @param other The secret to take the bytes of.
    */
    secret(secret&& other) noexcept : bytes_(other.bytes_) { detail::wipe_object(other.bytes_); }

    /**
     Takes the bytes of `other` over these, which are wiped first; `other` is wiped.

     @param other The secret to take the bytes of.
     @return This secret.
    */
    secret& operator=(secret&& other) noexcept {
        if (this != &other) {
            bytes_ = other.bytes_;
            detail::wipe_object(other.bytes_);
        }
        return *this;
    }

    /** Not copyable: a copy is asked for by name, with `clone`. */
    secret(secret const&) = delete;
    /** Not copyable: a copy is asked for by name, with `clone`. */
    secret& operator=(secret const&) = delete;

    /** Wipes the bytes. */
    ~secret() { detail::wipe_object(bytes_); }

    /**
     A copy of the bytes, which the caller then owns.

     @return A secret of the same bytes.
    */
    [[nodiscard]] secret clone() const noexcept {
        secret copy;
        copy.bytes_ = bytes_;
        return copy;
    }

    /**
     The bytes, to read.

     @return A view of the bytes.
    */
    [[nodiscard]] std::span<std::uint8_t const, N> bytes() const noexcept { return bytes_; }

    /**
     The bytes, for the library's engines to write.

     @return A writable view of the bytes.
    */
    [[nodiscard]] std::span<std::uint8_t, N> writable() noexcept { return bytes_; }

    /**
     The bytes, as a span of fixed size.

     @return A view of the bytes.
    */
    operator std::span<std::uint8_t const, N>() const noexcept { return bytes_; }

    /**
     The number of bytes.

     @return `N`.
    */
    static constexpr std::size_t size() noexcept { return N; }

private:
    std::array<std::uint8_t, N> bytes_{};
};

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_SECRET_HPP
