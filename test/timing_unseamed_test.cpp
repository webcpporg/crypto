// webcpp::secure::timing_guard, the guard crypto's public operations hold, in a program's build,
// without the seam: its constructor takes no source_location, on every target, so that no guarded
// function's name or header's path can reach a program. Built with WEBCPP_TEST_TIMING_READ_SELF
// (natively, at release), the program reads its own executable and finds neither the name of
// basic_chacha20_poly1305, whose seal it calls on a stand-in backend (the program links none), nor
// the path of aead.hpp, where seal's guard is declared.

#include <webcpp/crypto/ciphers/aead.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/secure/timing_guard.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstdint>
#include <source_location>
#include <span>
#include <type_traits>

#ifdef WEBCPP_TEST_TIMING_READ_SELF
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#endif

namespace webcpp::test {
namespace {

/** A backend tag for a generic layer's guard alone. */
struct unseamed_stand_in {};

}  // namespace
}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The stand-in's ChaCha20-Poly1305: every call succeeds; seal flips the data's bytes. */
template <>
struct aead_engine<families::chacha20_poly1305, test::unseamed_stand_in> {
    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> init(
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*key_bytes*/) noexcept {
        return {};
    }

    /** Flips every byte of the data, then succeeds. */
    [[nodiscard]] static boost::system::result<void> seal(
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> data,
        boost::hash2::digest<16>& /*tag*/) noexcept {
        for (auto& byte : data) {
            byte = static_cast<std::uint8_t>(~byte);
        }
        return {};
    }

    /** Succeeds. */
    [[nodiscard]] static boost::system::result<void> open(
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*state*/,
        std::span<std::uint8_t const> /*nonce_bytes*/,
        std::span<std::uint8_t const> /*associated_data_bytes*/, std::span<std::uint8_t> /*data*/,
        std::array<std::uint8_t, 16> const& /*tag*/) noexcept {
        return {};
    }

    /** Nothing to move. */
    static void move(
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*to*/,
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*from*/) noexcept {}

    /** Nothing to wipe. */
    static void reset(
        aead_state<families::chacha20_poly1305, test::unseamed_stand_in>& /*state*/) noexcept {}
};

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;
using cipher = crypto::ciphers::basic_chacha20_poly1305<crypto::families::chacha20_poly1305,
                                                        webcpp::test::unseamed_stand_in>;

static_assert(!std::is_constructible_v<webcpp::secure::timing_guard, bool, std::source_location>,
              "without the seam, timing_guard takes no source_location");
static_assert(!std::is_constructible_v<webcpp::secure::timing_guard, std::source_location>,
              "without the seam, timing_guard takes no source_location");
static_assert(std::is_nothrow_default_constructible_v<webcpp::secure::timing_guard>,
              "without the seam, timing_guard is constructed from nothing, and never throws");

// seal, on the stand-in, runs and answers as it does with the seam. Each call is outside
// BOOST_TEST, whose message would put the call's text in the program.
void seal_runs() {
    std::array<std::uint8_t, cipher::key_size> const key{};
    auto made = cipher::from_key(key);
    bool const made_one = made.has_value();
    if (!BOOST_TEST(made_one)) {
        return;
    }
    std::array<std::uint8_t, cipher::nonce_size> const nonce{};
    std::array<std::uint8_t, 4> data{1, 2, 3, 4};
    bool const sealed = made->seal(nonce, {}, data).has_value();
    BOOST_TEST(sealed);
    BOOST_TEST_EQ(data[0], 0xfe);
}

#ifdef WEBCPP_TEST_TIMING_READ_SELF
/**
 * The texts this program must not hold, kept in it with their last character changed, so that
 * the program's own constants are not what the search finds. Each is read through a volatile
 * pointer, which keeps it in the program whole: a search for a constant could otherwise compile
 * to comparisons with no copy of the text.
 */
constexpr std::string_view masked_name_text = "webcpp::crypto::ciphers::basic_chacha20_poly1305#";
constexpr std::string_view masked_path_text = "aead.hp#";

/**
 * A text of the program's, read where the compiler cannot see it.
 *
 * @param text A text of the program.
 * @return The same text, as the program holds it.
 */
std::string_view kept(std::string_view text) {
    char const* volatile const at = text.data();
    return {at, text.size()};
}

/**
 * A text this program must not hold, from its masked copy: the last character is restored at run
 * time, from a volatile the compiler cannot read ahead.
 *
 * @param masked The text, its last character replaced.
 * @param last The text's real last character.
 * @return The text.
 */
std::string unmasked(std::string_view masked, char last) {
    char volatile const restored = last;
    std::string text(masked);
    text.back() = restored;
    return text;
}

/**
 * Whether the bytes hold the text.
 *
 * @param bytes A file's bytes.
 * @param text The text.
 * @return Whether the text is somewhere in them.
 */
bool holds(std::vector<char> const& bytes, std::string_view text) {
    return !std::ranges::search(bytes, text).empty();
}

// The executable holds the masked texts, which shows the search reads it whole, and neither
// basic_chacha20_poly1305's name, as clang, GCC and MSVC write it in function_name(), nor the path
// of the header that declares seal's guard.
void executable_holds_no_location(char const* executable) {
    std::ifstream file(executable, std::ios::binary);
    if (!BOOST_TEST(file.is_open())) {
        return;
    }
    std::vector<char> const bytes{std::istreambuf_iterator<char>(file),
                                  std::istreambuf_iterator<char>()};
    std::string_view const masked_name = kept(masked_name_text);
    std::string_view const masked_path = kept(masked_path_text);
    BOOST_TEST(holds(bytes, masked_name));
    BOOST_TEST(holds(bytes, masked_path));
    BOOST_TEST(!holds(bytes, unmasked(masked_name, '<')));
    BOOST_TEST(!holds(bytes, unmasked(masked_path, 'p')));
}
#endif

}  // namespace

// NOLINTNEXTLINE(misc-const-correctness): main's arguments have the type the standard gives them
int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    seal_runs();
#ifdef WEBCPP_TEST_TIMING_READ_SELF
    if (BOOST_TEST(argc > 0)) {
        executable_holds_no_location(argv[0]);
    }
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
