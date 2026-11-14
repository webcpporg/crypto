# Working on crypto

webcpp's rules apply here: read the superproject's
[CODING-GUIDELINES.md](../../CODING-GUIDELINES.md)
(<https://github.com/webcpporg/webcpp/blob/main/CODING-GUIDELINES.md>) and its
[AGENTS.md](../../AGENTS.md)
(<https://github.com/webcpporg/webcpp/blob/main/AGENTS.md>) first. This file holds only what is
specific to crypto.

## What crypto is

- **webcpp's own library** (`"port-of": null`) over C backends: BearSSL, OpenSSL, ctaes and
  libsecp256k1. The algorithms are the backends'; crypto is the interface shaped as Boost.Hash2's.
- **No oracle.** The backends' own test vectors are the evidence; there is no second implementation
  to compare with.

## Cautions

- A backend's header supplies only the six traits; every guard lives in the algorithm types.
- A test of a backend is a `.cpp` of its own per backend, never a define that changes the backend
  of one source (spec section 4.3's pitfall).
- Every C library is unchanged upstream code. A moved pin is a change of its own
  (CODING-GUIDELINES.md chapter 5, rule 12).
