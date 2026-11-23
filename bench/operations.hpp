// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Each family's fixed operation, the one its size (test/sizes/) and its throughput
// (bench/throughput.cpp) measure: an operation of a family on a backend is the class
// `<family><Backend>` below, made once from a seed byte, outside what is measured. Its `run()` does
// the operation once and returns a byte of what it gave, which the caller prints or folds in, so
// that the optimiser keeps it; its `check()` says whether the operation's result is right (an open
// of what it sealed, a verification of what it signed, both sides of an agreement). An operation
// the library refuses ends the program: a figure measured on a failure would be a wrong one.
// `operation` names what is measured, the text crypto.json's family states (bench/collect.py
// checks that the two agree). A seal repeats under one key and one nonce: a measurement, never a
// use.

#ifndef WEBCPP_CRYPTO_BENCH_OPERATIONS_HPP
#define WEBCPP_CRYPTO_BENCH_OPERATIONS_HPP

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/curves/secp256k1/ellswift.hpp>
#include <webcpp/crypto/curves/secp256k1/musig.hpp>
#include <webcpp/crypto/curves/secp256k1/silent_payments.hpp>
#endif

#include <boost/system/result.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>
#include <utility>

namespace webcpp::crypto::bench {

// The bytes an AEAD seals at once.
inline constexpr std::size_t message_size = std::size_t{16} * 1024;

// Ends the program, naming the operation the library refused.
[[noreturn]] inline void refused(std::string_view what) {
    static_cast<void>(
        std::fprintf(stderr, "refused: %.*s\n", static_cast<int>(what.size()), what.data()));
    std::exit(1);
}

// N bytes, each of them value.
template <std::size_t N>
std::array<std::uint8_t, N> filled(std::uint8_t value) {
    std::array<std::uint8_t, N> bytes{};
    bytes.fill(value);
    return bytes;
}

// What a result holds, or the end of the program.
template <class Result>
auto take(Result&& result, std::string_view what) {
    if (!result) {
        refused(what);
    }
    return *std::forward<Result>(result);
}

// The baseline's operation (test/sizes/baseline.cpp): nothing of crypto, the harness alone, a
// result taken and refused as every operation's is, so that what a sized program adds to the
// baseline is its operation's code, not the harness's.
class nothing {
public:
    static constexpr std::string_view operation = "nothing: the harness alone";

    explicit nothing(std::uint8_t seed) : seed_(seed) {}

    [[nodiscard]] std::uint8_t run() const {
        boost::system::result<std::uint8_t> const made =
            seed_ == 0 ? boost::system::result<std::uint8_t>(error::backend_failure)
                       : boost::system::result<std::uint8_t>(seed_);
        return take(made, "nothing");
    }

    static bool check() { return true; }

private:
    std::uint8_t seed_;
};

// The encryption of one 16-byte block with a 256-bit key.
template <class Cipher>
class block_encryption {
public:
    static constexpr std::string_view operation = "encryption of one 16-byte block, 256-bit key";

    explicit block_encryption(std::uint8_t seed)
        : block_(filled<Cipher::block_size>(static_cast<std::uint8_t>(seed + 1U))),
          cipher_(take(Cipher::from_key(filled<Cipher::key_size>(seed)), "from_key")) {}

    std::uint8_t run() {
        if (!cipher_.encrypt(block_)) {
            refused("encrypt");
        }
        return block_[0];
    }

    bool check() {
        auto const plain = block_;
        static_cast<void>(run());
        bool const changed = block_ != plain;
        if (!cipher_.decrypt(block_)) {
            refused("decrypt");
        }
        return changed && block_ == plain;
    }

private:
    std::array<std::uint8_t, Cipher::block_size> block_{};
    Cipher cipher_;
};

// The seal of 16 KiB, in place, without associated data.
template <class Aead>
class aead_seal {
public:
    static constexpr std::string_view operation = "seal of 16 KiB, 256-bit key";

    explicit aead_seal(std::uint8_t seed)
        : nonce_(filled<Aead::nonce_size>(static_cast<std::uint8_t>(seed + 2U))),
          data_(filled<message_size>(seed)),
          aead_(take(Aead::from_key(filled<Aead::key_size>(seed)), "from_key")) {}

    std::uint8_t run() { return take(aead_.seal(nonce_, {}, data_), "seal").data()[0]; }

    bool check() {
        auto const plain = data_;
        auto const tag = take(aead_.seal(nonce_, {}, data_), "seal");
        bool const changed = data_ != plain;
        return changed && aead_.open(nonce_, {}, data_, tag).has_value() && data_ == plain;
    }

private:
    std::array<std::uint8_t, Aead::nonce_size> nonce_{};
    std::array<std::uint8_t, message_size> data_{};
    Aead aead_;
};

// AES-256-GCM.
template <class Backend>
using gcm = aead_seal<ciphers::gcm<ciphers::aes256<Backend>>>;

// The AES block cipher.
template <class Backend>
using aes_block = block_encryption<ciphers::aes256<Backend>>;

// ChaCha20-Poly1305 (RFC 8439).
template <class Backend>
using chacha20_poly1305 = aead_seal<ciphers::chacha20_poly1305<Backend>>;

// The original ChaCha20-Poly1305.
template <class Backend>
using chacha20_poly1305_original = aead_seal<ciphers::chacha20_poly1305_original<Backend>>;

// XChaCha20-Poly1305.
template <class Backend>
using xchacha20_poly1305 = aead_seal<ciphers::xchacha20_poly1305<Backend>>;

#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
// A BIP340 signature of a 32-byte message on secp256k1.
template <class Backend>
class secp256k1 {
public:
    static constexpr std::string_view operation = "BIP340 signature of a 32-byte message";

    explicit secp256k1(std::uint8_t seed)
        : message_(filled<32>(static_cast<std::uint8_t>(seed + 3U))),
          key_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")) {}

    std::uint8_t run() { return take(key_.sign(schnorr, message_, aux_), "sign").bytes()[0]; }

    bool check() {
        auto const signature = take(key_.sign(schnorr, message_, aux_), "sign");
        auto const public_key = take(key_.public_key(), "public_key");
        return crypto::verify(schnorr, signature, message_, public_key).has_value();
    }

private:
    std::array<std::uint8_t, 32> message_{};
    std::array<std::uint8_t, 32> aux_{};
    curves::secp256k1::basic_keypair<Backend> key_;
};

// The x coordinate of the ECDH shared point of a key pair and a peer's public key, unhashed,
// agree.
template <class Backend>
class secp256k1_ecdh_x {
public:
    static constexpr std::string_view operation =
        "x coordinate of the ECDH shared point with a peer's public key";

    explicit secp256k1_ecdh_x(std::uint8_t seed)
        : key_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")),
          peer_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                         filled<32>(static_cast<std::uint8_t>(seed + 6U))),
                     "from_secret")),
          peer_public_(take(peer_.public_key(), "public_key")) {}

    std::uint8_t run() {
        auto const shared = take(key_.agree(peer_public_), "agree");
        return shared.bytes()[0];
    }

    bool check() {
        auto const own_public = take(key_.public_key(), "public_key");
        auto const shared = take(key_.agree(peer_public_), "agree");
        auto const peer_shared = take(peer_.agree(own_public), "agree");
        return std::ranges::equal(shared.bytes(), peer_shared.bytes());
    }

private:
    curves::secp256k1::basic_keypair<Backend> key_;
    curves::secp256k1::basic_keypair<Backend> peer_;
    curves::secp256k1::public_key peer_public_;
};

// The public key recovered from a recoverable ECDSA signature of a 32-byte hash; the signature
// is made once, outside what is measured.
template <class Backend>
class secp256k1_recover {
public:
    static constexpr std::string_view operation =
        "public key recovered from an ECDSA signature of a 32-byte hash";

    explicit secp256k1_recover(std::uint8_t seed)
        : hash_(filled<32>(static_cast<std::uint8_t>(seed + 3U))),
          key_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")),
          signature_(take(key_.sign(ecdsa_sha256_recoverable, prehashed{hash_}), "sign")) {}

    std::uint8_t run() {
        auto const recovered = take(curves::secp256k1::recover<Backend>(
                                        ecdsa_sha256_recoverable, signature_, prehashed{hash_}),
                                    "recover");
        return recovered.compressed()[1];
    }

    bool check() {
        auto const recovered = take(curves::secp256k1::recover<Backend>(
                                        ecdsa_sha256_recoverable, signature_, prehashed{hash_}),
                                    "recover");
        return recovered == take(key_.public_key(), "public_key");
    }

private:
    std::array<std::uint8_t, 32> hash_{};
    curves::secp256k1::basic_keypair<Backend> key_;
    curves::secp256k1::recoverable_signature signature_;
};

// BIP 324's shared secret of a key pair and a peer, each known by its ElligatorSwift encoding.
template <class Backend>
class secp256k1_ellswift {
public:
    static constexpr std::string_view operation =
        "BIP 324 shared secret of two ElligatorSwift encodings";

    explicit secp256k1_ellswift(std::uint8_t seed)
        : key_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")),
          peer_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                         filled<32>(static_cast<std::uint8_t>(seed + 6U))),
                     "from_secret")),
          own_encoding_(
              take(curves::secp256k1::ellswift_create(key_, filled<32>(seed)), "ellswift_create")),
          peer_encoding_(take(curves::secp256k1::ellswift_create(
                                  peer_, filled<32>(static_cast<std::uint8_t>(seed + 7U))),
                              "ellswift_create")) {}

    std::uint8_t run() {
        auto const shared =
            take(curves::secp256k1::ellswift_xdh(key_, own_encoding_, peer_encoding_,
                                                 curves::secp256k1::ellswift_party::initiator),
                 "ellswift_xdh");
        return shared.bytes()[0];
    }

    bool check() {
        auto const shared =
            take(curves::secp256k1::ellswift_xdh(key_, own_encoding_, peer_encoding_,
                                                 curves::secp256k1::ellswift_party::initiator),
                 "ellswift_xdh");
        auto const peer_shared =
            take(curves::secp256k1::ellswift_xdh(peer_, own_encoding_, peer_encoding_,
                                                 curves::secp256k1::ellswift_party::responder),
                 "ellswift_xdh");
        return std::ranges::equal(shared.bytes(), peer_shared.bytes());
    }

private:
    curves::secp256k1::basic_keypair<Backend> key_;
    curves::secp256k1::basic_keypair<Backend> peer_;
    std::array<std::uint8_t, curves::secp256k1::ellswift_size> own_encoding_{};
    std::array<std::uint8_t, curves::secp256k1::ellswift_size> peer_encoding_{};
};

// A two-signer MuSig2 signature of a 32-byte message: both signers' nonces, the session, both
// partial signatures and their aggregate, the keys aggregated once outside what is measured.
template <class Backend>
class secp256k1_musig {
public:
    static constexpr std::string_view operation =
        "two-signer MuSig2 signature of a 32-byte message";

    explicit secp256k1_musig(std::uint8_t seed)
        : message_(filled<32>(static_cast<std::uint8_t>(seed + 3U))),
          first_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                          filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                      "from_secret")),
          second_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                           filled<32>(static_cast<std::uint8_t>(seed + 6U))),
                       "from_secret")),
          signers_key_(aggregate(first_, second_, space_)) {}

    std::uint8_t run() { return sign().bytes()[0]; }

    bool check() {
        return crypto::verify(schnorr, sign(), message_, signers_key_.xonly_public_key())
            .has_value();
    }

private:
    using space_type = std::array<std::byte, curves::secp256k1::musig::workspace_size(2)>;

    static curves::secp256k1::musig::aggregate_key aggregate(
        curves::secp256k1::basic_keypair<Backend> const& first,
        curves::secp256k1::basic_keypair<Backend> const& second, space_type& space) {
        std::array<curves::secp256k1::public_key, 2> const keys{
            take(first.public_key(), "public_key"),
            take(second.public_key(), "public_key"),
        };
        return take(curves::secp256k1::musig::key_aggregate<Backend>(keys, space), "key_aggregate");
    }

    curves::secp256k1::schnorr_signature sign() {
        namespace musig = curves::secp256k1::musig;
        auto first_nonce = take(musig::nonce_gen(first_, signers_key_, message_), "nonce_gen");
        auto second_nonce = take(musig::nonce_gen(second_, signers_key_, message_), "nonce_gen");
        std::array<musig::public_nonce, 2> const nonces{first_nonce.public_part,
                                                        second_nonce.public_part};
        auto const nonce_sum = take(musig::nonce_aggregate<Backend>(nonces, space_), "nonce_sum");
        auto const signing_session =
            take(musig::nonce_process<Backend>(nonce_sum, message_, signers_key_), "session");
        std::array<musig::partial_signature, 2> const parts{
            take(musig::partial_sign(first_, std::move(first_nonce.secret_part), signers_key_,
                                     signing_session),
                 "partial_sign"),
            take(musig::partial_sign(second_, std::move(second_nonce.secret_part), signers_key_,
                                     signing_session),
                 "partial_sign"),
        };
        return take(musig::partial_signature_aggregate<Backend>(signing_session, parts, space_),
                    "partial_signature_aggregate");
    }

    std::array<std::uint8_t, 32> message_{};
    alignas(std::max_align_t) space_type space_{};
    curves::secp256k1::basic_keypair<Backend> first_;
    curves::secp256k1::basic_keypair<Backend> second_;
    curves::secp256k1::musig::aggregate_key signers_key_;
};

// A silent payment output for one recipient, from one input's key pair.
template <class Backend>
class secp256k1_silent_payments {
public:
    static constexpr std::string_view operation = "a silent payment output for one recipient";

    explicit secp256k1_silent_payments(std::uint8_t seed)
        : scan_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                         filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                     "from_secret")),
          spend_key_(public_of(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                                        filled<32>(static_cast<std::uint8_t>(seed + 6U))),
                                    "from_secret"))),
          input_(take(curves::secp256k1::basic_keypair<Backend>::from_secret(
                          filled<32>(static_cast<std::uint8_t>(seed + 8U))),
                      "from_secret")),
          outpoint_(filled<curves::secp256k1::silent_payments::outpoint_size>(seed)) {}

    std::uint8_t run() { return send()[0]; }

    bool check() {
        namespace silent_payments = curves::secp256k1::silent_payments;
        std::array<std::array<std::uint8_t, 32>, 1> const outputs{send()};
        std::array<curves::secp256k1::public_key, 1> const input_keys{public_of(input_)};
        alignas(std::max_align_t)
            std::array<std::byte, silent_payments::summary_workspace_size(0, 1)>
                summary_space{};
        auto const summary = take(silent_payments::make_prevouts_summary<Backend>(
                                      outpoint_, {}, input_keys, summary_space),
                                  "make_prevouts_summary");
        std::array<silent_payments::found_output, 1> found{};
        alignas(std::max_align_t) std::array<std::byte, silent_payments::scan_workspace_size(1)>
            scan_space{};
        return take(silent_payments::scan_outputs(scan_, spend_key_, summary, outputs, found,
                                                  scan_space),
                    "scan_outputs") == 1;
    }

private:
    static curves::secp256k1::public_key public_of(
        curves::secp256k1::basic_keypair<Backend> const& key) {
        return take(key.public_key(), "public_key");
    }

    std::array<std::uint8_t, 32> send() {
        namespace silent_payments = curves::secp256k1::silent_payments;
        std::array<silent_payments::recipient, 1> const recipients{
            silent_payments::recipient{.scan_key = public_of(scan_), .spend_key = spend_key_}};
        std::array<curves::secp256k1::basic_keypair<Backend> const*, 1> const plain_inputs{&input_};
        std::array<std::array<std::uint8_t, 32>, 1> outputs{};
        alignas(std::max_align_t)
            std::array<std::byte, silent_payments::send_workspace_size(1, 0, 1)>
                space{};
        take(silent_payments::create_outputs<Backend>(recipients, outpoint_, {}, plain_inputs,
                                                      outputs, space),
             "create_outputs");
        return outputs[0];
    }

    curves::secp256k1::basic_keypair<Backend> scan_;
    curves::secp256k1::public_key spend_key_;
    curves::secp256k1::basic_keypair<Backend> input_;
    std::array<std::uint8_t, curves::secp256k1::silent_payments::outpoint_size> outpoint_{};
};
#endif

// An ECDSA signature of a 32-byte SHA-256 digest on P-256, `sign(ecdsa_sha256, prehashed{digest})`:
// RFC 6979's nonce, made low S.
template <class Backend>
class p256 {
public:
    static constexpr std::string_view operation = "ECDSA signature of a 32-byte SHA-256 digest";

    explicit p256(std::uint8_t seed)
        : digest_(filled<32>(static_cast<std::uint8_t>(seed + 3U))),
          key_(take(curves::p256::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")) {}

    std::uint8_t run() {
        return take(key_.sign(ecdsa_sha256, prehashed{digest_}), "sign").bytes()[0];
    }

    bool check() {
        auto const signature = take(key_.sign(ecdsa_sha256, prehashed{digest_}), "sign");
        auto const public_key = take(key_.public_key(), "public_key");
        return crypto::verify(ecdsa_sha256, signature, prehashed{digest_}, public_key)
                   .has_value() &&
               curves::p256::is_low_s(signature);
    }

private:
    std::array<std::uint8_t, 32> digest_{};
    curves::p256::basic_keypair<Backend> key_;
};

// The verification of an ECDSA signature of a 32-byte SHA-256 digest on P-256, `crypto::verify(
// ecdsa_sha256, signature, prehashed{digest}, public_key)`; the signature and the public key are
// made once, outside what is measured.
template <class Backend>
class p256_verify_ecdsa {
public:
    static constexpr std::string_view operation = "ECDSA verification of a 32-byte SHA-256 digest";

    explicit p256_verify_ecdsa(std::uint8_t seed)
        : digest_(filled<32>(static_cast<std::uint8_t>(seed + 3U))),
          key_(take(curves::p256::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")),
          public_key_(take(key_.public_key(), "public_key")),
          signature_(take(key_.sign(ecdsa_sha256, prehashed{digest_}), "sign")) {}

    std::uint8_t run() {
        take(crypto::verify(ecdsa_sha256, signature_, prehashed{digest_}, public_key_), "verify");
        return signature_.bytes()[0];
    }

    bool check() {
        auto other_bytes = signature_.bytes();
        other_bytes[63] ^= 1U;
        auto const other =
            take(curves::p256::ecdsa_signature::from_bytes(other_bytes), "from_bytes");
        return crypto::verify(ecdsa_sha256, signature_, prehashed{digest_}, public_key_)
                   .has_value() &&
               !crypto::verify(ecdsa_sha256, other, prehashed{digest_}, public_key_).has_value();
    }

private:
    std::array<std::uint8_t, 32> digest_{};
    curves::p256::basic_keypair<Backend> key_;
    curves::p256::basic_public_key<Backend> public_key_;
    curves::p256::ecdsa_signature signature_;
};

// The x coordinate of the ECDH shared point of a P-256 key pair and a peer's public key, agree.
template <class Backend>
class p256_ecdh_x {
public:
    static constexpr std::string_view operation =
        "x coordinate of the ECDH shared point with a peer's public key";

    explicit p256_ecdh_x(std::uint8_t seed)
        : key_(take(curves::p256::basic_keypair<Backend>::from_secret(
                        filled<32>(static_cast<std::uint8_t>(seed | 1U))),
                    "from_secret")),
          peer_(take(curves::p256::basic_keypair<Backend>::from_secret(
                         filled<32>(static_cast<std::uint8_t>(seed + 6U))),
                     "from_secret")),
          peer_public_(take(peer_.public_key(), "public_key")) {}

    std::uint8_t run() {
        auto const shared = take(key_.agree(peer_public_), "agree");
        return shared.bytes()[0];
    }

    bool check() {
        auto const own_public = take(key_.public_key(), "public_key");
        auto const shared = take(key_.agree(peer_public_), "agree");
        auto const peer_shared = take(peer_.agree(own_public), "agree");
        return std::ranges::equal(shared.bytes(), peer_shared.bytes());
    }

private:
    curves::p256::basic_keypair<Backend> key_;
    curves::p256::basic_keypair<Backend> peer_;
    curves::p256::basic_public_key<Backend> peer_public_;
};

// An Ed25519 signature of a 32-byte message.
template <class Backend>
class ed25519 {
public:
    static constexpr std::string_view operation = "signature of a 32-byte message";

    explicit ed25519(std::uint8_t seed)
        : message_(filled<32>(static_cast<std::uint8_t>(seed + 4U))),
          key_(take(curves::ed25519::basic_keypair<Backend>::from_secret(filled<32>(seed)),
                    "from_secret")) {}

    std::uint8_t run() { return take(key_.sign(eddsa, message_), "sign").bytes()[0]; }

    bool check() {
        auto const signature = take(key_.sign(eddsa, message_), "sign");
        auto const public_key = take(key_.public_key(), "public_key");
        return crypto::verify<Backend>(eddsa, signature, message_, public_key,
                                       curves::ed25519::strict)
            .has_value();
    }

private:
    std::array<std::uint8_t, 32> message_{};
    curves::ed25519::basic_keypair<Backend> key_;
};

// An X25519 agreement of a key pair with a peer's public key.
template <class Backend>
class x25519 {
public:
    static constexpr std::string_view operation = "agreement of a secret key and a public key";

    explicit x25519(std::uint8_t seed)
        : key_(take(curves::x25519::basic_keypair<Backend>::from_secret(filled<32>(seed)),
                    "from_secret")),
          peer_key_(take(curves::x25519::basic_keypair<Backend>::from_secret(
                             filled<32>(static_cast<std::uint8_t>(seed + 5U))),
                         "from_secret")),
          peer_public_(take(peer_key_.public_key(), "public_key")) {}

    std::uint8_t run() {
        auto const shared = take(key_.agree(peer_public_), "agree");
        return shared.bytes()[0];
    }

    bool check() {
        auto const own_public = take(key_.public_key(), "public_key");
        auto const shared = take(key_.agree(peer_public_), "agree");
        auto const peer_shared = take(peer_key_.agree(own_public), "agree");
        return std::ranges::equal(shared.bytes(), peer_shared.bytes());
    }

private:
    curves::x25519::basic_keypair<Backend> key_;
    curves::x25519::basic_keypair<Backend> peer_key_;
    curves::x25519::public_key peer_public_;
};

}  // namespace webcpp::crypto::bench

#endif  // WEBCPP_CRYPTO_BENCH_OPERATIONS_HPP
