// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// PEM's generic layer on a stand-in backend whose base64 decoder is lenient, as a later backend's
// may be: it takes non-zero bits after the last character's, and reads the first 64 characters
// of a longer text. pem::unarmour refuses what armour does not write itself (design D30), so
// that every backend gives libsodium's verdict: base64 that does not encode its bytes again to
// itself, padding on a line that is not the last, and a line longer than 64 characters, which
// the engine is never given. A backend that fails on the second pass leaves no byte of the DER
// in the output.

#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/pem.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace webcpp::test {
namespace {

/** A backend tag for PEM's generic layer alone. */
struct pem_stand_in {};

/** What the stand-in records, and when it fails. */
struct pem_stand_in_knobs {
    /** The longest text decode was given. */
    std::size_t longest = 0;
    /** The calls of decode so far. */
    std::size_t calls = 0;
    /** The call of decode, counted from 1, that fails; 0 for none. */
    std::size_t failing_call = 0;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knobs a test turns
pem_stand_in_knobs pem_stand_in_control{};

constexpr std::string_view alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's engine: canonical base64 out, lenient base64 in. */
template <>
struct pem_engine<families::pem, test::pem_stand_in> {
    /** Always ready. */
    [[nodiscard]] static boost::system::result<void> ready() noexcept { return {}; }

    /** The base64 of at most 48 bytes, with padding. */
    static void encode(std::span<std::uint8_t const> bytes, std::span<char> out) noexcept {
        std::size_t at = 0;
        for (std::size_t first = 0; first < bytes.size(); first += 3) {
            std::size_t const count = std::min<std::size_t>(3, bytes.size() - first);
            unsigned group = 0;
            for (std::size_t i = 0; i < 3; ++i) {
                group = (group << 8U) | (i < count ? bytes[first + i] : 0U);
            }
            for (std::size_t i = 0; i < 4; ++i) {
                out[at++] = i <= count ? test::alphabet[(group >> (18U - (6U * i))) & 63U] : '=';
            }
        }
    }

    /**
     * The bytes of base64, leniently: the first 64 characters alone, and any bits after the last
     * byte's; refuses a character outside the alphabet before the padding.
     */
    [[nodiscard]] static boost::system::result<std::size_t> decode(
        std::string_view text, std::span<std::uint8_t, 48> out) noexcept {
        auto& control = test::pem_stand_in_control;
        control.longest = std::max(control.longest, text.size());
        if (++control.calls == control.failing_call) {
            return error::backend_failure;
        }
        std::string_view const read(text.data(), std::min<std::size_t>(text.size(), 64));
        unsigned bits = 0;
        unsigned held = 0;
        std::size_t written = 0;
        for (char const c : read) {
            if (c == '=') {
                break;
            }
            auto const value = test::alphabet.find(c);
            if (value == std::string_view::npos) {
                return error::invalid_encoding;
            }
            bits = (bits << 6U) | static_cast<unsigned>(value);
            held += 6;
            if (held >= 8) {
                held -= 8;
                out[written++] = static_cast<std::uint8_t>((bits >> held) & 0xffU);
            }
        }
        return written;
    }
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
namespace pem = webcpp::crypto::pem;
namespace test = webcpp::test;
using stand_in = pem::algorithm<test::pem_stand_in>;

/** The PEM of der under the label X, on the stand-in. */
std::string armoured(std::span<std::uint8_t const> der) {
    std::string text(pem::armoured_size(1, der.size()), '#');
    auto const written = stand_in::armour("X", der, text);
    BOOST_TEST(written.has_value());
    return text;
}

/** Text refused with invalid_encoding on the stand-in, nothing written, the engine never given
 * more than 64 characters. */
void refused(std::string const& text, char const* what) {
    test::pem_stand_in_control = {};
    std::vector<std::uint8_t> out(text.size(), 0xa5);
    auto const read = stand_in::unarmour("X", text, out);
    if (!BOOST_TEST(!read && read.error() == crypto::error::invalid_encoding)) {
        static_cast<void>(std::fprintf(stderr, "accepted: %s\n", what));
    }
    BOOST_TEST(std::ranges::all_of(out, [](std::uint8_t b) { return b == 0xa5; }));
    BOOST_TEST_LE(test::pem_stand_in_control.longest, 64U);
}

void round_trip() {
    std::vector<std::uint8_t> der(100);
    for (std::size_t i = 0; i < der.size(); ++i) {
        der[i] = static_cast<std::uint8_t>(i * 7U);
    }
    std::string const text = armoured(der);
    test::pem_stand_in_control = {};
    std::vector<std::uint8_t> out(der.size());
    auto const read = stand_in::unarmour("X", text, out);
    BOOST_TEST(read.has_value() && *read == der.size() && out == der);
}

void lenient_inputs_refused() {
    // 44 bytes: one line of 60 characters ending "=", which carries two bits of padding.
    std::vector<std::uint8_t> const der(44, 0x11);
    std::string const text = armoured(der);
    std::size_t const padding = text.find("=\n");
    BOOST_TEST(padding != std::string::npos);
    // The character before "=" holds 4 bits of the last byte and 2 of padding: setting the
    // lowest of those makes base64 the lenient decoder takes, which encodes back otherwise.
    std::string changed = text;
    auto const at = test::alphabet.find(changed[padding - 1]);
    changed[padding - 1] = test::alphabet[at ^ 1U];
    refused(changed, "padding bits that are not zero");

    // A last line of 68 characters: the lenient decoder would read its first 64.
    std::vector<std::uint8_t> const full(48, 0x22);
    std::string const long_line = armoured(full);
    std::string const longer = long_line.substr(0, long_line.find("\n-----END")) + "AAAA" +
                               long_line.substr(long_line.find("\n-----END"));
    refused(longer, "a line of 68 characters");

    // An empty line after a full one: the base64 of nothing is nothing.
    std::string const empty_last = long_line.substr(0, long_line.find("\n-----END") + 1) + "\n" +
                                   long_line.substr(long_line.find("\n-----END") + 1);
    refused(empty_last, "an empty last line");

    // A line of 64 characters that ends with "==" before another line.
    std::vector<std::uint8_t> const first(46, 0x5a);
    std::vector<std::uint8_t> const second(10, 0x33);
    std::string const first_text = armoured(first);
    std::string const second_text = armoured(second);
    std::size_t const head = std::string_view("-----BEGIN X-----\n").size();
    refused(first_text.substr(0, head + 65) + second_text.substr(head),
            "padding at the end of a line that is not the last");
}

/** A backend that fails on the second pass leaves no byte of the DER in out. */
void second_pass_failure_wipes() {
    std::vector<std::uint8_t> der(60);
    std::ranges::fill(der, 0x77);
    std::string const text = armoured(der);
    test::pem_stand_in_control = {};
    // Two lines: the first pass decodes both, the second pass's second call fails.
    test::pem_stand_in_control.failing_call = 4;
    std::vector<std::uint8_t> out(der.size(), 0xa5);
    auto const read = stand_in::unarmour("X", text, out);
    BOOST_TEST(!read && read.error() == crypto::error::backend_failure);
    BOOST_TEST_EQ(test::pem_stand_in_control.calls, 4U);
    BOOST_TEST(std::ranges::none_of(out, [](std::uint8_t b) { return b == 0x77; }));
}

}  // namespace

int main() {
    round_trip();
    lenient_inputs_refused();
    second_pass_failure_wipes();
    return test::exit_status(boost::report_errors());
}
