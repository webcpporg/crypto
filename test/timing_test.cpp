// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// detail::timing_guard, with no backend: its seam fires once per guard on every target and names
// the function that holds the guard, which require_enters reads in the spellings of clang, GCC
// and MSVC; where the CPU has DIT, a guard sets it for its scope and clears it after when it was
// clear, leaves it set when it was set, and nests; constant_time_equal enters its own guard. Built
// with WEBCPP_TEST_TIMING_THREADS (timing_threads, native, with threads), a guard on one thread
// leaves another's DIT clear. P-256's normalize_low_s and is_low_s, which call no backend, enter no
// guard: this program links none, and curves/p256.hpp needs none to declare them; nor does
// erase_secret, which only stores zeroes.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/constant_time_equal.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/detail/timing.hpp>
#include <webcpp/crypto/erase_secret.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/p256_data.hpp"

#include <boost/core/lightweight_test.hpp>
#include <boost/hash2/digest.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#ifdef WEBCPP_TEST_TIMING_THREADS
#include <future>
#include <thread>
#endif

namespace {

namespace detail = webcpp::crypto::detail;

namespace seam_probe {

/** Holds a guard, as a public function does, for seam_names_function. */
void guarded_function() {
    webcpp::crypto::detail::timing_guard const guard;
}

/** Calls guarded_function and holds no guard of its own, as a function that forgot its own. */
void forwarding_function() {
    guarded_function();
}

}  // namespace seam_probe

/**
 * Sets or clears DIT for this thread, as a program can, so that a test starts from a known state;
 * only where the CPU has DIT, since the instruction traps on a CPU without it.
 */
void force_dit([[maybe_unused]] bool set) {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (!detail::cpu_has_dit()) {
        return;
    }
    detail::write_dit(set ? detail::dit_bit : 0);
#endif
}

// Constructing a guard raises the seam's count by exactly one, on every target.
void seam_fires() {
    std::size_t const before = webcpp::test::timing_entries;
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(webcpp::test::timing_entries, before + 1);
    }
    BOOST_TEST_EQ(webcpp::test::timing_entries, before + 1);
}

// The seam records the function that holds the first guard a call enters, as the compiler spells
// it, and require_enters' reading of it finds that function and no other.
void seam_names_function() {
    webcpp::test::timing_first_entry = nullptr;
    seam_probe::forwarding_function();
    if (BOOST_TEST(webcpp::test::timing_first_entry != nullptr)) {
        std::string_view const entered = webcpp::test::timing_first_entry;
        BOOST_TEST(webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(entered,
                                                 webcpp::test::function_named("guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::forwarding_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("other::guarded_function")));
        BOOST_TEST(!webcpp::test::names_function(
            entered, webcpp::test::function_named("seam_probe::guarded")));
    }
    webcpp::test::timing_first_entry = nullptr;
}

// require_enters' reading of a function_name() in the spellings of clang, GCC and MSVC, whatever
// compiles this test: a free forwarder and the member it forwards to, a constructor, operators,
// overloads told apart by a parameter, and lambdas, which are never a public function.
void names_function_spellings() {
    auto const names = [](std::string_view entered, std::string_view spelled) {
        return webcpp::test::names_function(entered, webcpp::test::function_named(spelled));
    };
    BOOST_TEST(names("int ns::pem::armour(int) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("static int ns::pem::algorithm<int>::armour(int) [B = int]", "pem::armour"));
    BOOST_TEST(
        names("static int ns::pem::algorithm<B>::armour(int) [with B = int]", "algorithm::armour"));
    BOOST_TEST(names("int __cdecl ns::pem::armour<struct ns::b>(int)", "pem::armour"));
    BOOST_TEST(!names("int __cdecl ns::pem::algorithm<struct ns::b>::armour(int)", "pem::armour"));
    BOOST_TEST(
        names("struct ns::gcm<int> &__cdecl ns::gcm<int>::operator =(struct ns::gcm<int> &&)",
              "gcm::operator="));
    BOOST_TEST(
        !names("bool __cdecl ns::operator ==(struct ns::pk,struct ns::pk)", "ns::operator="));
    BOOST_TEST(
        names("bool __cdecl ns::operator ==(struct ns::pk,struct ns::pk)", "ns::operator=="));
    BOOST_TEST(names("ns::gcm<C>::gcm(ns::gcm<C>&&) [with C = int]", "gcm::gcm"));
    BOOST_TEST(
        names("bool ns::equal(std::span<const unsigned char>, std::span<const unsigned char>)",
              "ns::equal(span"));
    BOOST_TEST(
        !names("bool ns::equal(std::span<const unsigned char>, std::span<const unsigned char>)",
               "ns::equal(digest"));
    BOOST_TEST(
        names("bool __cdecl ns::equal<16>(const class ns::digest<16> &)", "ns::equal(digest"));
    // A name in the return type or a parameter type is not the function's own.
    BOOST_TEST(!names("int ns::other(ns::pem::armour<int>, int) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("int ns::other(ns::pem::armour(int)) [with B = int]", "pem::armour"));
    BOOST_TEST(!names("ns::pem::armour<int> ns::from_key(int) [B = int]", "pem::armour"));
    BOOST_TEST(!names("struct ns::pem::armour<int> __cdecl ns::from_key<int>(int)", "pem::armour"));
    BOOST_TEST(!names("ns::algorithm<ns::pem::armour<int>>::seal(int)", "pem::armour"));
    BOOST_TEST(names("ns::pem::armour<int> ns::pem::armour(ns::pem::armour<int>)", "pem::armour"));
    // A function named without a scope never matches.
    BOOST_TEST(!names("int ns::pem::armour(int) [with B = int]", "armour"));
    BOOST_TEST(names("auto ns::pk::operator<=>(const pk &) const", "pk::operator<=>"));
    BOOST_TEST(
        names("auto __cdecl ns::pk::operator <=>(const struct ns::pk &) const", "pk::operator<=>"));
    BOOST_TEST(!names("auto ns::f()::(anonymous class)::operator()() const", "ns::f"));
    BOOST_TEST(!names("auto ns::f()::(lambda)::operator()() const", "ns::f"));
    BOOST_TEST(!names("ns::f()::<lambda()>", "ns::f"));
    BOOST_TEST(!names("auto __cdecl ns::f::<lambda_1>::operator ()(void) const", "ns::f"));
}

// GCC writes a trailing requires-clause after the parameter list, before the template arguments:
// its parentheses are not the function's own.
void names_function_requires_clause() {
    constexpr std::string_view entered =
        "auto ns::to_x25519(const Value&) requires requires(const Value& v) {v->to_x25519();} "
        "[with Value = ns::pk]";
    BOOST_TEST(
        webcpp::test::names_function(entered, webcpp::test::function_named("ns::to_x25519")));
    BOOST_TEST(
        !webcpp::test::names_function(entered, webcpp::test::function_named("pk::to_x25519")));
}

// MSVC writes the exception specification of a function that may throw after its parameters,
// clang and GCC none: crypto::from_secret and crypto::generate of secp256k1's key pair, whose
// memory resource may throw, are read as their own in either spelling.
void names_function_exception_specifications() {
    auto const names = [](std::string_view entered, std::string_view spelled) {
        return webcpp::test::names_function(entered, webcpp::test::function_named(spelled));
    };
    BOOST_TEST(
        names("class ns::result<class ns::kp<struct ns::b>> __cdecl "
              "ns::crypto::from_secret<class ns::kp<struct ns::b>,const class std::array<unsigned "
              "char,32>&>(const class std::array<unsigned char,32> &) noexcept(false)",
              "crypto::from_secret"));
    BOOST_TEST(
        names("class ns::result<class ns::kp<struct ns::b>> __cdecl "
              "ns::crypto::generate<class ns::kp<struct ns::b>,>(void) noexcept(false)",
              "crypto::generate"));
    BOOST_TEST(names("int __cdecl ns::pem::armour<struct ns::b>(int) noexcept", "pem::armour"));
    BOOST_TEST(names("int __cdecl ns::pk::compare(int) const noexcept(true)", "pk::compare(int"));
    // The specification is not a parameter list: its words never name the function.
    BOOST_TEST(!names("int __cdecl ns::crypto::from_secret<int>(int) noexcept(false)",
                      "crypto::from_secret(false"));
    BOOST_TEST(!names("int __cdecl ns::other(int) noexcept(ns::pem::armour(int))", "pem::armour"));
}

// From clear: set inside a guard, clear after it. Where the guard does not apply, never set.
void guard_sets_and_clears() {
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST(!detail::dit_is_set());
}

// From set, as a program sets it: still set after a guard.
void guard_leaves_set_bit() {
    force_dit(true);
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    {
        detail::timing_guard const guard;
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    force_dit(false);
    BOOST_TEST(!detail::dit_is_set());
}

// From clear: set inside both guards and after the inner one, clear after the outer one.
void nested_guards() {
    force_dit(false);
    {
        detail::timing_guard const outer;
        {
            detail::timing_guard const inner;
            BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
        }
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    BOOST_TEST(!detail::dit_is_set());
}

// Both overloads of constant_time_equal enter a guard, and leave DIT as they found it.
void constant_time_equal_enters() {
    force_dit(false);
    std::array<std::uint8_t, 16> const first{};
    std::array<std::uint8_t, 16> const second{};
    webcpp::test::require_enters(
        "constant_time_equal(span, span)", "crypto::constant_time_equal(span", [&first, &second] {
            BOOST_TEST(webcpp::crypto::constant_time_equal(std::span<std::uint8_t const>(first),
                                                           std::span<std::uint8_t const>(second)));
        });
    boost::hash2::digest<16> const first_digest{};
    boost::hash2::digest<16> const second_digest{};
    webcpp::test::require_enters(
        "constant_time_equal(digest, digest)", "crypto::constant_time_equal(digest",
        [&first_digest, &second_digest] {
            BOOST_TEST(webcpp::crypto::constant_time_equal(first_digest, second_digest));
        });
    BOOST_TEST(!detail::dit_is_set());
}

// P-256's low-S functions are arithmetic on public bytes, with no backend: no guard.
void p256_low_s_unguarded() {
    namespace p256 = webcpp::crypto::curves::p256;
    namespace data = webcpp::test::p256;
    auto const sample = p256::ecdsa_signature::from_bytes(data::rfc6979_sample);
    auto const test = p256::ecdsa_signature::from_bytes(data::rfc6979_test);
    if (!BOOST_TEST(sample.has_value()) || !BOOST_TEST(test.has_value())) {
        return;
    }
    webcpp::test::uncovered("p256::normalize_low_s", [&sample] {
        auto const normalized = p256::normalize_low_s(*sample);
        BOOST_TEST(normalized.has_value() && normalized->bytes() == data::rfc6979_sample_low_s);
    });
    webcpp::test::uncovered("p256::is_low_s", [&test] { BOOST_TEST(p256::is_low_s(*test)); });
}

// erase_secret calls no backend: it stores zeroes through detail::wipe, and holds no guard.
void erase_secret_unguarded() {
    webcpp::test::uncovered("erase_secret", [] {
        std::array<std::uint8_t, 16> const zero{};
        std::array<std::uint8_t, 16> password{};
        password.fill(0x5a);
        webcpp::crypto::erase_secret(password);
        BOOST_TEST(password == zero);
    });
}

#ifdef WEBCPP_TEST_TIMING_THREADS
// While a guard holds DIT on this thread, another thread reads it clear. The other thread is
// started before the guard, so that it cannot inherit the state at its creation (Linux's clone
// copies PSTATE), and reads it only once the guard is entered.
void other_thread_untouched() {
    force_dit(false);
    std::promise<void> guard_entered;
    std::promise<bool> other_reading;
    std::thread other([entered = guard_entered.get_future(), &other_reading]() mutable {
        entered.wait();
        other_reading.set_value(detail::dit_is_set());
    });
    {
        detail::timing_guard const guard;
        guard_entered.set_value();
        BOOST_TEST(!other_reading.get_future().get());
        BOOST_TEST_EQ(detail::dit_is_set(), detail::cpu_has_dit());
    }
    other.join();
    BOOST_TEST(!detail::dit_is_set());
}
#endif

}  // namespace

int main() {
    seam_fires();
    seam_names_function();
    names_function_spellings();
    names_function_requires_clause();
    names_function_exception_specifications();
    guard_sets_and_clears();
    guard_leaves_set_bit();
    nested_guards();
    constant_time_equal_enters();
    p256_low_s_unguarded();
    erase_secret_unguarded();
#ifdef WEBCPP_TEST_TIMING_THREADS
    other_thread_untouched();
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
