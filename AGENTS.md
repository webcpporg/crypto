# Working on crypto

webcpp's rules apply here: read the superproject's
[CODING-GUIDELINES.md](../../CODING-GUIDELINES.md)
(<https://github.com/webcpporg/webcpp/blob/main/CODING-GUIDELINES.md>) and its
[AGENTS.md](../../AGENTS.md)
(<https://github.com/webcpporg/webcpp/blob/main/AGENTS.md>) first. This file holds only what is
specific to crypto.

## What crypto is

- **webcpp's own library** (`"port-of": null`) over C backends: BearSSL, OpenSSL, ctaes,
  libsecp256k1 and libsodium (the superproject's `/third_party//sodium`, shared with
  webcpp::hash). The algorithms are the backends'; crypto is the interface shaped as Boost.Hash2's.
  crypto depends on config, hash and secure: the timing guard, `erase_secret`,
  `constant_time_equal`, `secret<N>` and `declassify` are webcpp::secure's, with no copy and no
  alias in crypto.
- **No oracle.** No original runs beside crypto: the evidence is the published vectors (the GCM
  specification's cases, Wycheproof, FIPS 197, RFC 8439 and RFC 8032, BIP340 and BIP341), the
  backends' own suites in the lane `c-suites`, and the agreement tests, which compare two backends
  on random inputs.
- **One default backend per family and target, with its reason; no profile.** The capability table
  (`supports_v`, `default_backend_t`) is generated, never read from a measurement.

## The generators

- `doc/tables/generate.py` reads `doc/tables/crypto.json`, the test Jamfiles, the message tests and
  the superproject's Jamfile fixtures, and writes `doc/generated/*.adoc`, `doc/llms.txt`,
  `include/webcpp/crypto/detail/capabilities.hpp`, `detail/defaults.hpp`, the defaults' aliases in
  `build.jam`, `test/capabilities_test.cpp` and the Ed25519 cases' table from
  `meta/ed25519_cases.json`. Each says it is generated: never edit it, change `crypto.json` or the
  generator and run it again. `generate.py --check` writes nothing and fails on a difference; the
  doc build runs it and `generate_test.py` (its tests, written first).
- A new family, backend, message test, fixture or MSVC case needs its `crypto.json` entry in the
  same commit (`fixes` for each message, `fixtures` for each fixture, `lane` for the constant-time
  lane's paths); the generator names what is missing.
- `generate.py --sizes <json>...` reads the own lane `sizes` (built at `variant=release`) into
  `doc/tables/sizes.json`; `doc/performance.json` is `bench/collect.py`'s, release builds only,
  the throughput (`--exe`) and the timing guard's cost (`--timing`, natively). Nothing that states
  a size or a speed is typed by hand.

## Cautions

- An algorithm type does every guard; a backend's header supplies only the eight traits of
  `detail/engines.hpp` (`block_state`, `block_engine`, `gcm_state`, `gcm_engine`, `aead_state`,
  `aead_engine`, `secretbox_state`, `secretbox_engine`), the two of `detail/p_curves.hpp` per
  P-curve (`p_curve_state`, `p_curve_engine`) and, for the other curves, `public_key_encryption`
  and `key_exchange`, the functions of its own header.
- A new public function that calls a backend holds `secure::timing_guard` as its first statement
  (`secure::timing_guard const timing_scope;`, webcpp::secure's,
  `<webcpp/secure/timing_guard.hpp>`, which sets arm64's DIT for the call) and joins the coverage
  test of its backend, `test/timing_coverage_<backend>_test.cpp`, which checks through the seam
  that each call entered its own guard. The seam support (`test/support/timing_seam.hpp`) counts
  crypto's own guards by their file, under `include/webcpp/crypto/`, in `timing_entries`, and
  every guard, hash's and secure's included, in `timing_all_entries`. A function that only copies
  or encodes bytes, with no backend call, holds none.
- Every wipe of a key, a state or a failed output is `secure::erase_secret` over a span
  (`<webcpp/secure/erase_secret.hpp>`; an object that is not an array as
  `std::span(&object, 1)`); a verdict webcpp branches on is marked with `secure::declassify(x)`,
  which the constant-time lane's `WEBCPP_SECURE_CT_VALGRIND` and `WEBCPP_SECURE_CT_MSAN` turn into
  the checker's mark; a returned secret is a `secure::secret<N>`, a comparison of secrets
  `secure::constant_time_equal`, each always written qualified.
- The constant-time lane's P-256 paths (`test/constant_time/paths.hpp`): BearSSL's ECDSA signing
  branches on its own verdicts, listed for memcheck in `bearssl_verdicts.supp`, which a later
  P-curve's signing joins; MemorySanitizer counts BearSSL's window selections public (masks of the
  form `(q | -q) >> 31`), so the public point and `agree` are checked traced by memcheck alone.
- A test of a backend is a `.cpp` of its own per backend, never a define that changes the backend
  of one source (spec section 4.3's pitfall).
- Every C library is upstream code, unchanged except where CODING-GUIDELINES.md chapter 5 rule 1
  allows a security fix on the mirror's `webcpp` branch (BearSSL: 32381d6, ECDSA's nonce
  decoding); a moved pin carries that commit. A moved pin is a change of its own (rule 12).
- X25519's constant time on wasip2 is an open finding (the page's constant-time table): do not
  describe it as a pass.
