#pragma once

#include <optional>
#include <vector>

#include "Group.h"

namespace pkeet
{

class LGZ22
{
public:
    static constexpr uint8_t kDomainH1 = 0x01;
    static constexpr uint8_t kDomainH2 = 0x02;
    static constexpr uint8_t kDomainH3 = 0x03;

    static constexpr size_t kMessageAndUBytes = 2 * kZpBytes;
    static constexpr size_t kLambdaBytes      = 32;

    struct UserKey   { Bn x, y; Pt X, Y; };
    struct ServerKey { Bn xc;   Pt Xc;   };
    struct TesterKey { Bn xt;   Pt Xt;   };

    struct Ciphertext
    {
        Pt c1, c2;
        std::array<uint8_t, kMessageAndUBytes> c3;
        Pt c4;
        std::array<uint8_t, kLambdaBytes> c5;
    };

    struct Trapdoor
    {
        std::vector<Pt> td1;
        Bn td2;
    };

    explicit LGZ22(const Group &G) : G_(G) {}

    UserKey   userGen() const;
    ServerKey serverGen() const;
    TesterKey testerGen() const;
    Bn        randomMessage() const;

    Ciphertext encrypt(const BIGNUM *m, const EC_POINT *X, const EC_POINT *Y, const EC_POINT *Xc) const;
    std::optional<Bn> decrypt(const Ciphertext &ct, const BIGNUM *x) const;

    Trapdoor auth(const Ciphertext &ct, const BIGNUM *y, const BIGNUM *xc,
                  const std::vector<const EC_POINT *> &testerKeys) const;

    bool test(const Ciphertext &cti, const Trapdoor &tdi,
              const Ciphertext &ctj, const Trapdoor &tdj,
              const BIGNUM *xtw, const EC_POINT *Xc) const;

    Pt delta(const Ciphertext &ct, const Trapdoor &td, const BIGNUM *eta) const;

    Bn   H2(const EC_POINT *P) const;
    void H1(const EC_POINT *P, uint8_t out[kMessageAndUBytes]) const;
    void H3(const Ciphertext &ct, const uint8_t mu[kMessageAndUBytes], uint8_t out[kLambdaBytes]) const;

private:
    const Group &G_;
};

}
