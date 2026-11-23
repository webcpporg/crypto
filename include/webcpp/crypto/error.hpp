// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The errors of webcpp::crypto, in the category `webcpp.crypto`.

 @see "Errors", in the guide.
*/
#ifndef WEBCPP_CRYPTO_ERROR_HPP
#define WEBCPP_CRYPTO_ERROR_HPP

#include <webcpp/crypto/config.hpp>

#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

namespace webcpp::crypto {

/**
 Why an operation of webcpp::crypto failed.

 The values are fixed and never reused.

 @see "Errors", in the guide.
*/
enum class error : int {
    /** A key of another size than the algorithm's `key_size`, or a secret key not of 32 bytes. */
    invalid_key_size = 1,
    /**
     * A nonce of a size the algorithm does not accept: a GCM nonce that is empty or longer than
     * 128 bytes, another AEAD's or a box's nonce of another size than its own.
     */
    invalid_nonce_size = 2,
    /** A tag given to `open` or `verify` that is not of 16 bytes. */
    invalid_tag_size = 3,
    /**
     * A buffer or data of a size the function does not accept: data for a block cipher that is
     * not a whole number of blocks, an output shorter than the function needs, or the incremental
     * open's `decrypt` past the authenticated length and `end_open` short of it.
     */
    invalid_input_size = 4,
    /** A message or associated data longer than the algorithm allows. */
    message_too_long = 5,
    /** The tag does not match: the message or its associated data changed, or the key differs. */
    authentication_failed = 6,
    /** An object moved from, or the incremental seal or open called out of order. */
    invalid_state = 7,
    /**
     * The system's or the browser's generator failed, or secp256k1's `generate` drew four times
     * and none was a secret key.
     */
    entropy_unavailable = 8,
    /** A secret scalar, a secret key or a tweak, that is zero or not below the group order. */
    invalid_secret_key = 9,
    /**
     * A public key of the wrong size, with a prefix other than 02 or 03 (33 bytes) or 04 (65
     * bytes), or not a point of the curve.
     */
    invalid_public_key = 10,
    /**
     * A signature that does not verify, or is not a valid encoding: not strict DER, or an r or
     * an s that is zero or not below the group order.
     */
    invalid_signature = 11,
    /** A backend failed where its contract says it does not. */
    backend_failure = 12,
    /**
     * OpenSSL's memory functions could not be installed: OpenSSL has already allocated, or another
     * party installed its own.
     *
     * Returned by `backends::openssl::install_memory_functions`, with
     * `WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE`.
     */
    memory_functions_refused = 13,
    /**
     * OpenSSL's memory functions are not webcpp::crypto's, so a `from_key` of the OpenSSL backend
     * refuses to run, with `WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE`.
     */
    memory_functions_not_installed = 14,
    /** A public key of small order, or one that gives an all-zero shared secret. */
    weak_public_key = 15,
    /** An encoding that is not a canonical element of the group. */
    invalid_point = 16,
    /** A scalar that is not reduced, or zero where zero is refused. */
    invalid_scalar = 17,
    /** Padding that cannot be removed, whatever the cause. */
    invalid_padding = 18,
    /**
     * Hexadecimal, base64, PEM, or a key's DER form that does not decode, or is not the one
     * encoding the format allows.
     */
    invalid_encoding = 19,
    /** A KEM or RSA ciphertext of another size than the key's. */
    invalid_ciphertext_size = 20,
};

namespace detail {

/** The message of a value of @ref error, or the unknown message for a value it does not define. */
inline const char* message_of(int error_value) noexcept {
    switch (static_cast<error>(error_value)) {
        case error::invalid_key_size: return "the key is not of the algorithm's size";
        case error::invalid_nonce_size: return "the nonce is not of a size the algorithm accepts";
        case error::invalid_tag_size: return "the tag is not of 16 bytes";
        case error::invalid_input_size: return "the buffer is not of a size the function accepts";
        case error::message_too_long: return "the message is longer than the algorithm allows";
        case error::authentication_failed: return "the authentication tag does not match";
        case error::invalid_state: return "the object was moved from, or the call is out of order";
        case error::entropy_unavailable: return "the system's generator of entropy failed";
        case error::invalid_secret_key:
            return "the secret key or tweak is zero or not below the group order";
        case error::invalid_public_key: return "the public key is not a point of the curve";
        case error::invalid_signature:
            return "the signature does not verify or is not a valid encoding";
        case error::backend_failure: return "the backend failed where it should not";
        case error::memory_functions_refused:
            return "OpenSSL's memory functions cannot be installed: OpenSSL has already "
                   "allocated, or another party installed its own. Call "
                   "backends::openssl::install_memory_functions() as the first statement of "
                   "main, before anything uses OpenSSL.";
        case error::memory_functions_not_installed:
            return "OpenSSL's memory functions are not webcpp::crypto's. Call "
                   "backends::openssl::install_memory_functions() as the first statement of "
                   "main, and let nothing else call CRYPTO_set_mem_functions.";
        case error::weak_public_key:
            return "the public key is weak: of small order, or the shared secret is zero";
        case error::invalid_point: return "the encoding is not a canonical element of the group";
        case error::invalid_scalar: return "the scalar is not reduced, or is zero";
        case error::invalid_padding: return "the padding is not valid";
        case error::invalid_encoding: return "the encoding does not decode";
        case error::invalid_ciphertext_size: return "the ciphertext is not of the key's size";
    }
    return "unknown webcpp.crypto error";
}

/**
 A constant category with a fixed identity, so it holds no mutable state.

 @note The identity is the ASCII of "crypto" followed by two zero bytes.
*/
class category final : public boost::system::error_category {
public:
    /** Constructs the category with its fixed identity. */
    constexpr category() noexcept : boost::system::error_category(0x63727970746f0000ULL) {}

    /** The category's name, "webcpp.crypto". */
    const char* name() const noexcept override { return "webcpp.crypto"; }

    /** The message of the error `error_value`, as @ref message_of spells it. */
    std::string message(int error_value) const override { return message_of(error_value); }

    /**
     Copies the message of the error `error_value` into `text_buffer`, cut to fit `byte_count` bytes
     with its terminating zero, and returns the whole message, a static text.
    */
    const char* message(int error_value, char* text_buffer,
                        std::size_t byte_count) const noexcept override {
        const char* message_text = message_of(error_value);
        if (text_buffer != nullptr && byte_count != 0) {
            const std::string_view message_spelling(message_text);
            const std::size_t size_limit = byte_count - 1;
            const std::size_t copied_count =
                message_spelling.size() < size_limit ? message_spelling.size() : size_limit;
            std::memcpy(text_buffer, message_spelling.data(), copied_count);
            text_buffer[copied_count] = '\0';
        }
        return message_text;
    }
};

/** The one category of crypto's errors, which @ref error_category returns. */
inline constexpr category the_category{};

}  // namespace detail

/**
 The category of every @ref error.

 Its `name()` is "webcpp.crypto", and its `message(value)` the message of the error, or
 "unknown webcpp.crypto error" for a value @ref error does not define.

 @return The category, a constant with a fixed identity.
 @see "Errors", in the guide.
*/
inline const boost::system::error_category& error_category() noexcept {
    return detail::the_category;
}

/**
 Makes the `error_code` of an @ref error, as its implicit conversion does.

 @param error_value The error.
 @return `error_value` as an `error_code` of the category @ref error_category.
*/
inline boost::system::error_code make_error_code(error error_value) noexcept {
    return {static_cast<int>(error_value), error_category()};
}

}  // namespace webcpp::crypto

namespace boost::system {
template <>
struct is_error_code_enum<webcpp::crypto::error> : std::true_type {};
}  // namespace boost::system

#endif  // WEBCPP_CRYPTO_ERROR_HPP
