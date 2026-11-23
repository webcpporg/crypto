// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 PEM (RFC 7468): a key's DER form as text, between `-----BEGIN <label>-----` and
 `-----END <label>-----`, in base64 lines of 64 characters, each ended by a line feed, the form
 OpenSSL writes; read strictly, as the one text that armouring the DER again gives (design D30).

 The family's default backend, libsodium on every target, whose base64 runs in constant time,
 is included when the program links it; a program that uses the family without linking it stops
 where it calls it, with the Jamfile line that links it.

 @see "Key formats: SPKI, PKCS#8 and PEM", in the guide.
*/
#ifndef WEBCPP_CRYPTO_PEM_HPP
#define WEBCPP_CRYPTO_PEM_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::crypto::detail {

/**
 * The base64 of PEM on a backend; the primary refuses (defined at the end of this header). A
 * backend's specialisation provides `ready()`, `encode(bytes, out)` of at most 48 bytes into
 * their whole base64 with padding, and `decode(text, out)` of at most 64 characters, which
 * returns the bytes' count, or `invalid_encoding` for text that is not base64 with padding.
 */
template <class Name, class Backend>
struct pem_engine;

/** The text before a label in PEM's first line. */
inline constexpr std::string_view pem_begin = "-----BEGIN ";
/** The text before a label in PEM's last line. */
inline constexpr std::string_view pem_end = "-----END ";
/** The text after a label in PEM's first and last lines, with the line feed. */
inline constexpr std::string_view pem_close = "-----\n";
/** The bytes of one full line of base64, and its characters. */
inline constexpr std::size_t pem_line_bytes = 48;
/** The characters of one full line of base64. */
inline constexpr std::size_t pem_line_characters = 64;

/**
 * Whether a label is one RFC 7468 allows and that is not empty: printable ASCII characters, with
 * single spaces or hyphens between them, as in `PUBLIC KEY`.
 */
[[nodiscard]] constexpr bool pem_label_allowed(std::string_view pem_label) noexcept {
    auto const separator_test = [](char pem_character) {
        return pem_character == ' ' || pem_character == '-';
    };
    auto const printable_test = [](char pem_character) {
        return pem_character >= '!' && pem_character <= '~';
    };
    if (pem_label.empty() || separator_test(pem_label.front()) ||
        separator_test(pem_label.back())) {
        return false;
    }
    for (std::size_t character_index = 0; character_index < pem_label.size(); ++character_index) {
        char const pem_character = pem_label[character_index];
        if (separator_test(pem_character)) {
            if (separator_test(pem_label[character_index - 1])) {
                return false;
            }
        } else if (!printable_test(pem_character)) {
            return false;
        }
    }
    return true;
}

/**
 * The characters of `pem_text` from `character_index`, at most `character_count` of them, none past
 * its end: a `std::string_view::substr` that never throws.
 */
[[nodiscard]] constexpr std::string_view pem_part(std::string_view pem_text,
                                                  std::size_t character_index,
                                                  std::size_t character_count) noexcept {
    if (character_index > pem_text.size()) {
        return {};
    }
    return {pem_text.data() + character_index,
            (std::min)(character_count, pem_text.size() - character_index)};
}

/**
 * Whether two lines of base64 are the same, in a time that does not depend on their characters,
 * which encode a private key's bytes in PEM of a PKCS#8: through `constant_time_equal`.
 */
[[nodiscard]] inline bool pem_same_line(std::span<char const> first_line,
                                        std::span<char const> second_line) noexcept {
    if (first_line.size() != second_line.size() || first_line.size() > pem_line_characters) {
        return false;
    }
    std::array<std::uint8_t, pem_line_characters> first_bytes{};
    std::array<std::uint8_t, pem_line_characters> second_bytes{};
    std::ranges::transform(first_line, first_bytes.begin(), [](char pem_character) {
        return static_cast<std::uint8_t>(pem_character);
    });
    std::ranges::transform(second_line, second_bytes.begin(), [](char pem_character) {
        return static_cast<std::uint8_t>(pem_character);
    });
    bool const bytes_equal = constant_time_equal(first_bytes, second_bytes);
    wipe_object(first_bytes);
    wipe_object(second_bytes);
    return bytes_equal;
}

}  // namespace webcpp::crypto::detail

namespace webcpp::crypto::pem {

/** The label of a public key's SPKI, as OpenSSL writes it. */
inline constexpr std::string_view public_key_label = "PUBLIC KEY";
/** The label of a private key's PKCS#8, as OpenSSL writes it. */
inline constexpr std::string_view private_key_label = "PRIVATE KEY";

/**
 * The size of the PEM text of `der_size` bytes under a label of `label_size` characters: its
 * first line, its lines of base64 of 64 characters each with a line feed, and its last line.
 *
 * @param label_size The label's characters, 10 for `PUBLIC KEY`.
 * @param der_size The DER's bytes.
 * @return The characters `armour` writes.
 */
[[nodiscard]] constexpr std::size_t armoured_size(std::size_t label_size,
                                                  std::size_t der_size) noexcept {
    std::size_t const character_count = ((der_size + 2) / 3) * 4;
    std::size_t const line_count =
        (character_count + detail::pem_line_characters - 1) / detail::pem_line_characters;
    return detail::pem_begin.size() + label_size + detail::pem_close.size() + character_count +
           line_count + detail::pem_end.size() + label_size + detail::pem_close.size();
}

/**
 * PEM on a backend: the type `supports_v` names, whose functions the free functions below call.
 *
 * @tparam Backend The backend; by default the family's (`default_backend_t<families::pem>`).
 */
template <class Backend = default_backend_t<families::pem>>
struct algorithm {
    /** The family, for `supports_v`. */
    using family_type = families::pem;
    /** The algorithm, for `supports_v`: the family's one name. */
    using name_type = families::pem;
    /** The backend. */
    using backend_type = Backend;

    /**
     * Writes DER as PEM under a label: `-----BEGIN <label>-----`, the base64 in lines of 64
     * characters, `-----END <label>-----`, each line ended by a line feed alone.
     *
     * Tip: the PEM of a PKCS#8 is the private key: a program wipes `output_characters`, or seals
     * it, when it is done.
     *
     * @param pem_label The label, as `public_key_label`; printable ASCII, with single spaces or
     * hyphens between its characters.
     * @param der_bytes The bytes.
     * @param output_characters At least `armoured_size(pem_label.size(), der_bytes.size())`
     * characters, of which as many are written.
     * @return The characters written; `invalid_input_size` for an `output_characters` too small;
     * `invalid_encoding` for a label PEM cannot carry; `backend_failure`. Nothing is written on
     * a refusal.
     */
    [[nodiscard]] static boost::system::result<std::size_t> armour(
        std::string_view pem_label, std::span<std::uint8_t const> der_bytes,
        std::span<char> output_characters) noexcept {
        detail::timing_guard const timing_scope;
        if (!detail::pem_label_allowed(pem_label)) {
            return error::invalid_encoding;
        }
        std::size_t const armour_size = armoured_size(pem_label.size(), der_bytes.size());
        if (output_characters.size() < armour_size) {
            return error::invalid_input_size;
        }
        auto const library_ready = engine::ready();
        if (!library_ready) {
            return library_ready.error();
        }
        auto write_position = output_characters.begin();
        auto const append_text = [&write_position](std::string_view pem_text) {
            write_position = std::ranges::copy(pem_text, write_position).out;
        };
        append_text(detail::pem_begin);
        append_text(pem_label);
        append_text(detail::pem_close);
        for (std::size_t line_start = 0; line_start < der_bytes.size();
             line_start += detail::pem_line_bytes) {
            auto const line_bytes = der_bytes.subspan(
                line_start, (std::min)(detail::pem_line_bytes, der_bytes.size() - line_start));
            std::size_t const character_count = ((line_bytes.size() + 2) / 3) * 4;
            engine::encode(line_bytes, std::span<char>(write_position, character_count));
            write_position += static_cast<std::ptrdiff_t>(character_count);
            *write_position++ = '\n';
        }
        append_text(detail::pem_end);
        append_text(pem_label);
        append_text(detail::pem_close);
        return armour_size;
    }

    /**
     * The DER of PEM under a label, refused unless the text is exactly what `armour` writes:
     * nothing before the first line or after the last line's line feed, the label expected in
     * both, lines of 64 characters but the last, line feeds alone, and base64 that encodes its
     * bytes again to the same characters.
     *
     * OpenSSL's `PEM_write_*` give this form.
     *
     * @param pem_label The label expected, as `private_key_label`.
     * @param pem_text The PEM text.
     * @param output_bytes At least as many bytes as the DER has; a quarter less than
     * `pem_text.size()` is always enough.
     * @return The bytes written; `invalid_encoding`; `invalid_input_size` for an `output_bytes` too
     * small; `backend_failure`. Nothing is written on a refusal, and a backend that fails after it
     * began to write leaves zeros.
     */
    [[nodiscard]] static boost::system::result<std::size_t> unarmour(
        std::string_view pem_label, std::string_view pem_text,
        std::span<std::uint8_t> output_bytes) noexcept {
        detail::timing_guard const timing_scope;
        if (!detail::pem_label_allowed(pem_label)) {
            return error::invalid_encoding;
        }
        std::size_t const head_size =
            detail::pem_begin.size() + pem_label.size() + detail::pem_close.size();
        std::size_t const tail_size =
            detail::pem_end.size() + pem_label.size() + detail::pem_close.size();
        if (pem_text.size() < head_size + tail_size ||
            !lined(pem_text, 0, detail::pem_begin, pem_label) ||
            !lined(pem_text, pem_text.size() - tail_size, detail::pem_end, pem_label)) {
            return error::invalid_encoding;
        }
        std::string_view const body_text =
            detail::pem_part(pem_text, head_size, pem_text.size() - head_size - tail_size);
        auto const library_ready = engine::ready();
        if (!library_ready) {
            return library_ready.error();
        }
        // First every line is checked, decoded into a buffer and encoded again; then, once the
        // whole text is known to be the one encoding and its size to fit, decoded into
        // `output_bytes`.
        std::size_t byte_count = 0;
        bool lines_accepted = true;
        for_each_line(
            body_text,
            [&](std::string_view line_text, bool last_line,
                std::span<std::uint8_t, detail::pem_line_bytes> line_bytes) {
                // The engine is given 1 to 64 characters, whatever the text holds.
                if (line_text.empty() || line_text.size() > detail::pem_line_characters) {
                    return false;
                }
                auto const decode_result = engine::decode(line_text, line_bytes);
                if (!decode_result) {
                    return false;
                }
                // Read unchecked, which never throws: decoded holds a count.
                std::size_t const decoded_count = decode_result.unsafe_value();
                // Padding ends the last line alone: any other line holds 48 bytes, so that, once
                // encoded again to itself, it is of 64 characters.
                if (!last_line && decoded_count != detail::pem_line_bytes) {
                    return false;
                }
                std::array<char, detail::pem_line_characters> reencoded_line{};
                std::size_t const character_count = ((decoded_count + 2) / 3) * 4;
                engine::encode(line_bytes.first(decoded_count),
                               std::span(reencoded_line).first(character_count));
                bool const line_equal = detail::pem_same_line(
                    line_text, std::span(reencoded_line).first(character_count));
                detail::wipe_object(reencoded_line);
                byte_count += decoded_count;
                return line_equal;
            },
            lines_accepted);
        if (!lines_accepted) {
            return error::invalid_encoding;
        }
        if (output_bytes.size() < byte_count) {
            return error::invalid_input_size;
        }
        auto write_position = output_bytes.begin();
        for_each_line(
            body_text,
            [&](std::string_view line_text, bool /*last_line*/,
                std::span<std::uint8_t, detail::pem_line_bytes> line_bytes) {
                auto const decode_result = engine::decode(line_text, line_bytes);
                if (!decode_result) {
                    return false;
                }
                write_position = std::ranges::copy(line_bytes.first(decode_result.unsafe_value()),
                                                   write_position)
                                     .out;
                return true;
            },
            lines_accepted);
        // The lines decoded once decode again: a backend that disagrees with itself fails, and
        // the bytes it wrote, a private key's in a PKCS#8, are wiped.
        if (!lines_accepted) {
            detail::wipe(output_bytes.data(),
                         static_cast<std::size_t>(write_position - output_bytes.begin()));
            return error::backend_failure;
        }
        return byte_count;
    }

private:
    using engine = detail::pem_engine<families::pem, Backend>;

    // Whether `pem_text` holds, at `character_index`, the line `opening_marker`, the label and
    // `-----` with its line feed.
    [[nodiscard]] static bool lined(std::string_view pem_text, std::size_t character_index,
                                    std::string_view opening_marker,
                                    std::string_view pem_label) noexcept {
        return detail::pem_part(pem_text, character_index, opening_marker.size()) ==
                   opening_marker &&
               detail::pem_part(pem_text, character_index + opening_marker.size(),
                                pem_label.size()) == pem_label &&
               detail::pem_part(pem_text,
                                character_index + opening_marker.size() + pem_label.size(),
                                detail::pem_close.size()) == detail::pem_close;
    }

    // Calls `visit_line(line_text, last_line, line_bytes)` on each line of the body, each ended by
    // a line feed, with a buffer of a line's bytes that is wiped after each; `lines_accepted`
    // becomes false, and the walk stops, at a body that does not end with a line feed or at the
    // first line `visit_line` refuses.
    template <class Visit>
    static void for_each_line(std::string_view body_text, Visit visit_line,
                              bool& lines_accepted) noexcept {
        std::array<std::uint8_t, detail::pem_line_bytes> line_bytes{};
        std::size_t line_start = 0;
        while (lines_accepted && line_start < body_text.size()) {
            std::size_t const line_end = body_text.find('\n', line_start);
            if (line_end == std::string_view::npos) {
                lines_accepted = false;
                break;
            }
            lines_accepted =
                visit_line(detail::pem_part(body_text, line_start, line_end - line_start),
                           line_end + 1 == body_text.size(), std::span(line_bytes));
            detail::wipe_object(line_bytes);
            line_start = line_end + 1;
        }
    }
};

/**
 * Writes DER as PEM under a label: `algorithm<Backend>::armour`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param pem_label The label, as `public_key_label`.
 * @param der_bytes The bytes.
 * @param output_characters At least `armoured_size(pem_label.size(), der_bytes.size())` characters.
 * @return The characters written; `invalid_input_size`; `invalid_encoding`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::pem>>
[[nodiscard]] boost::system::result<std::size_t> armour(
    std::string_view pem_label, std::span<std::uint8_t const> der_bytes,
    std::span<char> output_characters) noexcept {
    detail::timing_guard const timing_scope;
    return algorithm<Backend>::armour(pem_label, der_bytes, output_characters);
}

/**
 * The DER of PEM under a label, strictly: `algorithm<Backend>::unarmour`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param pem_label The label expected, as `private_key_label`.
 * @param pem_text The PEM text.
 * @param output_bytes At least as many bytes as the DER has.
 * @return The bytes written; `invalid_encoding`; `invalid_input_size`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::pem>>
[[nodiscard]] boost::system::result<std::size_t> unarmour(
    std::string_view pem_label, std::string_view pem_text,
    std::span<std::uint8_t> output_bytes) noexcept {
    detail::timing_guard const timing_scope;
    return algorithm<Backend>::unarmour(pem_label, pem_text, output_bytes);
}

}  // namespace webcpp::crypto::pem

namespace webcpp::crypto::detail {

/**
 * PEM's engine on a backend whose header does not specialise it: the family's refusal, which
 * names what the program needs (`detail/capabilities.hpp`). Its functions are never called: the
 * refusal stops the build where the class is instantiated, and they keep the compiler from
 * adding errors of their own after it; those that return report `backend_failure`, so that a
 * path the refusal missed fails closed.
 */
template <class Name, class Backend>
struct pem_engine {
    WEBCPP_CRYPTO_DETAIL_REFUSE_PEM(Backend);

    /** Never called; fails closed. */
    [[nodiscard]] static boost::system::result<void> ready() noexcept {
        return error::backend_failure;
    }

    /** Never called. */
    template <class... Arguments>
    static void encode(Arguments&&... /*arguments*/) noexcept {}

    /** Never called; fails closed. */
    template <class... Arguments>
    [[nodiscard]] static boost::system::result<std::size_t> decode(
        Arguments&&... /*arguments*/) noexcept {
        return error::backend_failure;
    }
};

}  // namespace webcpp::crypto::detail

// The default backend's engine, when the program links it (design D32): libsodium on every
// target. Its header specialises it for this header, wherever it was first included.
#if defined(WEBCPP_CRYPTO_DETAIL_DEFAULT_PEM_SODIUM) && defined(WEBCPP_CRYPTO_HAS_SODIUM)
#include <webcpp/crypto/backends/sodium.hpp>
#endif

#endif  // WEBCPP_CRYPTO_PEM_HPP
