#pragma once

#include <optional>
#include <vector>

#include "Group.h"

namespace pkeet
{

class ModifiedPKEETFDA
{
public:
    static constexpr uint8_t kDomainH1 = 0x11;
    static constexpr uint8_t kDomainH2 = 0x12;
    static constexpr uint8_t kDomainH3 = 0x13;
    static constexpr uint8_t kDomainH4 = 0x14;

    static constexpr size_t kMessageBytes = 32;
    static constexpr size_t kC4Bytes      = kMessageBytes + 2 * kZpBytes;
    static constexpr size_t kH4Bytes      = 2 * kWideHashBytes;

    using Message = std::array<uint8_t, kMessageBytes>;

    struct UserKey   { Bn x, y; Pt X, Y; };
    struct TesterKey { Bn xt;   Pt Xt;   };

    struct Ciphertext
    {
        Pt C1, C2;
        Bn C3;
        Bytes C4;
    };

    struct Trapdoor
    {
        Pt D;
        std::vector<Bn> a;
    };

    struct DecryptionResult
    {
        Message M;
        Bn tau;
    };

    struct RhoSigma
    {
        Bn rho, sigma;
    };

    enum class AuthMode { VerifyCiphertext, SkipVerification };

    explicit ModifiedPKEETFDA(const Group &G) : G_(G) {}

    UserKey   userGen() const;
    TesterKey testerGen() const;
    Message   randomMessage() const;

    Ciphertext encrypt(const Message &M, const EC_POINT *X, const EC_POINT *Y) const;
    std::optional<Message> decrypt(const Ciphertext &ct, const BIGNUM *x, const BIGNUM *y) const;
    std::optional<DecryptionResult> decryptWithTau(const Ciphertext &ct, const BIGNUM *x, const BIGNUM *y) const;

    std::optional<Trapdoor> auth(const Ciphertext &ct, const UserKey &uk,
                                 const std::vector<const EC_POINT *> &testerKeys,
                                 AuthMode mode = AuthMode::VerifyCiphertext) const;

    bool test(const Ciphertext &cti, const Trapdoor &tdi,
              const Ciphertext &ctj, const Trapdoor &tdj,
              const TesterKey &tester) const;

    Bn       H1(const Message &M) const;
    Bn       H2(const EC_POINT *P) const;
    void     H3(const EC_POINT *C1, const EC_POINT *C2, const BIGNUM *C3, const EC_POINT *Z, uint8_t out[kC4Bytes]) const;
    RhoSigma H4(const EC_POINT *Xt, const EC_POINT *D, const EC_POINT *W) const;

    static constexpr size_t ciphertextBytes() { return 2 * kPointBytes + kZpBytes + kC4Bytes; }

private:
    bool wellFormedForTest(const Ciphertext &ct, const Trapdoor &td) const;
    std::optional<Bn> recoverK(const Ciphertext &ct, const Trapdoor &td, const TesterKey &tester) const;

    const Group &G_;
};

}
