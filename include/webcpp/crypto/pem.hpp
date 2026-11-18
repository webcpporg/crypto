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

#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/detail/defaults.hpp>
#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/detail/wipe.hpp>
#include <webcpp/crypto/equal.hpp>
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
[[nodiscard]] constexpr bool pem_label_allowed(std::string_view label) noexcept {
    auto const separator = [](char c) { return c == ' ' || c == '-'; };
    auto const printable = [](char c) { return c >= '!' && c <= '~'; };
    if (label.empty() || separator(label.front()) || separator(label.back())) {
        return false;
    }
    for (std::size_t at = 0; at < label.size(); ++at) {
        char const c = label[at];
        if (separator(c)) {
            if (separator(label[at - 1])) {
                return false;
            }
        } else if (!printable(c)) {
            return false;
        }
    }
    return true;
}

/**
 * Whether two lines of base64 are the same, in a time that does not depend on their characters,
 * which encode a private key's bytes in PEM of a PKCS#8: through `equal`.
 */
[[nodiscard]] inline bool pem_same_line(std::span<char const> first_line,
                                        std::span<char const> second_line) noexcept {
    if (first_line.size() != second_line.size() || first_line.size() > pem_line_characters) {
        return false;
    }
    std::array<std::uint8_t, pem_line_characters> first_bytes{};
    std::array<std::uint8_t, pem_line_characters> second_bytes{};
    std::ranges::transform(first_line, first_bytes.begin(),
                           [](char c) { return static_cast<std::uint8_t>(c); });
    std::ranges::transform(second_line, second_bytes.begin(),
                           [](char c) { return static_cast<std::uint8_t>(c); });
    bool const same = equal(first_bytes, second_bytes);
    wipe_object(first_bytes);
    wipe_object(second_bytes);
    return same;
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
    std::size_t const characters = ((der_size + 2) / 3) * 4;
    std::size_t const lines =
        (characters + detail::pem_line_characters - 1) / detail::pem_line_characters;
    return detail::pem_begin.size() + label_size + detail::pem_close.size() + characters + lines +
           detail::pem_end.size() + label_size + detail::pem_close.size();
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
     * Tip: the PEM of a PKCS#8 is the private key: a program wipes `out`, or seals it, when it is
     * done.
     *
     * @param label The label, as `public_key_label`; printable ASCII, with single spaces or
     * hyphens between its characters.
     * @param der The bytes.
     * @param out At least `armoured_size(label.size(), der.size())` characters, of which as many
     * are written.
     * @return The characters written; `invalid_input_size` for an `out` too small;
     * `invalid_encoding` for a label PEM cannot carry; `backend_failure`. Nothing is written on
     * a refusal.
     */
    [[nodiscard]] static boost::system::result<std::size_t> armour(
        std::string_view label, std::span<std::uint8_t const> der, std::span<char> out) noexcept {
        if (!detail::pem_label_allowed(label)) {
            return error::invalid_encoding;
        }
        std::size_t const size = armoured_size(label.size(), der.size());
        if (out.size() < size) {
            return error::invalid_input_size;
        }
        auto const ready = engine::ready();
        if (!ready) {
            return ready.error();
        }
        auto at = out.begin();
        auto const put = [&at](std::string_view text) { at = std::ranges::copy(text, at).out; };
        put(detail::pem_begin);
        put(label);
        put(detail::pem_close);
        for (std::size_t first = 0; first < der.size(); first += detail::pem_line_bytes) {
            auto const line =
                der.subspan(first, std::min(detail::pem_line_bytes, der.size() - first));
            std::size_t const characters = ((line.size() + 2) / 3) * 4;
            engine::encode(line, std::span<char>(at, characters));
            at += static_cast<std::ptrdiff_t>(characters);
            *at++ = '\n';
        }
        put(detail::pem_end);
        put(label);
        put(detail::pem_close);
        return size;
    }

    /**
     * The DER of PEM under a label, refused unless the text is exactly what `armour` writes:
     * nothing before the first line or after the last line's line feed, the label expected in
     * both, lines of 64 characters but the last, line feeds alone, and base64 that encodes its
     * bytes again to the same characters.
     *
     * OpenSSL's `PEM_write_*` give this form.
     *
     * @param label The label expected, as `private_key_label`.
     * @param text The PEM text.
     * @param out At least as many bytes as the DER has; a quarter less than `text.size()` is
     * always enough.
     * @return The bytes written; `invalid_encoding`; `invalid_input_size` for an `out` too small;
     * `backend_failure`. Nothing is written on a refusal, and a backend that fails after it began
     * to write leaves zeros.
     */
    [[nodiscard]] static boost::system::result<std::size_t> unarmour(
        std::string_view label, std::string_view text, std::span<std::uint8_t> out) noexcept {
        if (!detail::pem_label_allowed(label)) {
            return error::invalid_encoding;
        }
        std::size_t const head = detail::pem_begin.size() + label.size() + detail::pem_close.size();
        std::size_t const tail = detail::pem_end.size() + label.size() + detail::pem_close.size();
        if (text.size() < head + tail || !lined(text, 0, detail::pem_begin, label) ||
            !lined(text, text.size() - tail, detail::pem_end, label)) {
            return error::invalid_encoding;
        }
        std::string_view const body = text.substr(head, text.size() - head - tail);
        auto const ready = engine::ready();
        if (!ready) {
            return ready.error();
        }
        // First every line is checked, decoded into a buffer and encoded again; then, once the
        // whole text is known to be the one encoding and its size to fit, decoded into out.
        std::size_t size = 0;
        bool accepted = true;
        for_each_line(
            body,
            [&](std::string_view line, bool last,
                std::span<std::uint8_t, detail::pem_line_bytes> bytes) {
                // The engine is given 1 to 64 characters, whatever the text holds.
                if (line.empty() || line.size() > detail::pem_line_characters) {
                    return false;
                }
                auto const decoded = engine::decode(line, bytes);
                // Padding ends the last line alone: any other line holds 48 bytes, so that, once
                // encoded again to itself, it is of 64 characters.
                if (!decoded || (!last && *decoded != detail::pem_line_bytes)) {
                    return false;
                }
                std::array<char, detail::pem_line_characters> again{};
                std::size_t const characters = ((*decoded + 2) / 3) * 4;
                engine::encode(bytes.first(*decoded), std::span(again).first(characters));
                bool const same = detail::pem_same_line(line, std::span(again).first(characters));
                detail::wipe_object(again);
                size += *decoded;
                return same;
            },
            accepted);
        if (!accepted) {
            return error::invalid_encoding;
        }
        if (out.size() < size) {
            return error::invalid_input_size;
        }
        auto at = out.begin();
        for_each_line(
            body,
            [&](std::string_view line, bool /*last*/,
                std::span<std::uint8_t, detail::pem_line_bytes> bytes) {
                auto const decoded = engine::decode(line, bytes);
                if (!decoded) {
                    return false;
                }
                at = std::ranges::copy(bytes.first(*decoded), at).out;
                return true;
            },
            accepted);
        // The lines decoded once decode again: a backend that disagrees with itself fails, and
        // the bytes it wrote, a private key's in a PKCS#8, are wiped.
        if (!accepted) {
            detail::wipe(out.data(), static_cast<std::size_t>(at - out.begin()));
            return error::backend_failure;
        }
        return size;
    }

private:
    using engine = detail::pem_engine<families::pem, Backend>;

    // Whether text holds, at `at`, the line `opening`, the label and `-----` with its line feed.
    [[nodiscard]] static bool lined(std::string_view text, std::size_t at, std::string_view opening,
                                    std::string_view label) noexcept {
        return text.substr(at, opening.size()) == opening &&
               text.substr(at + opening.size(), label.size()) == label &&
               text.substr(at + opening.size() + label.size(), detail::pem_close.size()) ==
                   detail::pem_close;
    }

    // Calls visit(line, last, bytes) on each line of the body, each ended by a line feed, with a
    // buffer of a line's bytes that is wiped after each; accepted becomes false, and the walk
    // stops, at a body that does not end with a line feed or at the first line visit refuses.
    template <class Visit>
    static void for_each_line(std::string_view body, Visit visit, bool& accepted) noexcept {
        std::array<std::uint8_t, detail::pem_line_bytes> bytes{};
        std::size_t start = 0;
        while (accepted && start < body.size()) {
            std::size_t const end = body.find('\n', start);
            if (end == std::string_view::npos) {
                accepted = false;
                break;
            }
            accepted =
                visit(body.substr(start, end - start), end + 1 == body.size(), std::span(bytes));
            detail::wipe_object(bytes);
            start = end + 1;
        }
    }
};

/**
 * Writes DER as PEM under a label: `algorithm<Backend>::armour`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param label The label, as `public_key_label`.
 * @param der The bytes.
 * @param out At least `armoured_size(label.size(), der.size())` characters.
 * @return The characters written; `invalid_input_size`; `invalid_encoding`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::pem>>
[[nodiscard]] boost::system::result<std::size_t> armour(std::string_view label,
                                                        std::span<std::uint8_t const> der,
                                                        std::span<char> out) noexcept {
    return algorithm<Backend>::armour(label, der, out);
}

/**
 * The DER of PEM under a label, strictly: `algorithm<Backend>::unarmour`.
 *
 * @tparam Backend The backend; by default the family's.
 * @param label The label expected, as `private_key_label`.
 * @param text The PEM text.
 * @param out At least as many bytes as the DER has.
 * @return The bytes written; `invalid_encoding`; `invalid_input_size`; `backend_failure`.
 */
template <class Backend = default_backend_t<families::pem>>
[[nodiscard]] boost::system::result<std::size_t> unarmour(std::string_view label,
                                                          std::string_view text,
                                                          std::span<std::uint8_t> out) noexcept {
    return algorithm<Backend>::unarmour(label, text, out);
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
