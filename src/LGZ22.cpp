#include "LGZ22.h"

#include <openssl/crypto.h>

namespace pkeet
{

LGZ22::UserKey LGZ22::userGen() const
{
    UserKey k;
    k.x = G_.randZpStar();
    k.y = G_.randZpStar();
    k.X = G_.expG(k.x.get());
    k.Y = G_.expG(k.y.get());
    return k;
}

LGZ22::ServerKey LGZ22::serverGen() const
{
    ServerKey k;
    k.xc = G_.randZpStar();
    k.Xc = G_.expG(k.xc.get());
    return k;
}

LGZ22::TesterKey LGZ22::testerGen() const
{
    TesterKey k;
    k.xt = G_.randZpStar();
    k.Xt = G_.expG(k.xt.get());
    return k;
}

Bn LGZ22::randomMessage() const
{
    return G_.randZpStar();
}

void LGZ22::H1(const EC_POINT *P, uint8_t out[kMessageAndUBytes]) const
{
    Group::shake256(kDomainH1, {G_.encodeCompressedOrZeroForIdentity(P)}, out, kMessageAndUBytes);
}

Bn LGZ22::H2(const EC_POINT *P) const
{
    return G_.hashToZp(kDomainH2, {G_.encodeCompressedOrZeroForIdentity(P)});
}

void LGZ22::H3(const Ciphertext &ct, const uint8_t mu[kMessageAndUBytes], uint8_t out[kLambdaBytes]) const
{
    Group::shake256(kDomainH3,
                    {G_.encodeCompressedOrZeroForIdentity(ct.c1.get()),
                     G_.encodeCompressedOrZeroForIdentity(ct.c2.get()),
                     ct.c3,
                     G_.encodeCompressedOrZeroForIdentity(ct.c4.get()),
                     ByteView(mu, kMessageAndUBytes)},
                    out, kLambdaBytes);
}

static void concatMessageAndU(const ZpBytes &m, const ZpBytes &u, uint8_t mu[LGZ22::kMessageAndUBytes])
{
    std::copy(m.begin(), m.end(), mu);
    std::copy(u.begin(), u.end(), mu + kZpBytes);
}

LGZ22::Ciphertext LGZ22::encrypt(const BIGNUM *m, const EC_POINT *X, const EC_POINT *Y, const EC_POINT *Xc) const
{
    Bn u = G_.randZpStar();
    Bn v = G_.randZpStar();

    Ciphertext ct;
    ct.c1 = G_.expG(u.get());
    ct.c2 = G_.expG(v.get());

    uint8_t mu[kMessageAndUBytes];
    concatMessageAndU(G_.encodeZp(m), G_.encodeZp(u.get()), mu);

    uint8_t mask[kMessageAndUBytes];
    H1(G_.exp(X, u.get()).get(), mask);
    for (size_t i = 0; i < kMessageAndUBytes; i++)
        ct.c3[i] = mask[i] ^ mu[i];

    Bn h2PlusM = G_.add(H2(G_.exp(Xc, v.get()).get()).get(), m);
    Pt Yv = G_.exp(Y, v.get());
    ct.c4 = G_.mul(Yv.get(), G_.expG(h2PlusM.get()).get());

    H3(ct, mu, ct.c5.data());
    return ct;
}

std::optional<Bn> LGZ22::decrypt(const Ciphertext &ct, const BIGNUM *x) const
{
    uint8_t mask[kMessageAndUBytes];
    H1(G_.exp(ct.c1.get(), x).get(), mask);

    uint8_t mu[kMessageAndUBytes];
    for (size_t i = 0; i < kMessageAndUBytes; i++)
        mu[i] = ct.c3[i] ^ mask[i];

    Bn m = G_.decodeZpUnreduced(mu);
    Bn u = G_.decodeZpUnreduced(mu + kZpBytes);

    if (!G_.eq(ct.c1.get(), G_.expG(u.get()).get()))
        return std::nullopt;

    uint8_t expectedC5[kLambdaBytes];
    H3(ct, mu, expectedC5);
    if (CRYPTO_memcmp(expectedC5, ct.c5.data(), kLambdaBytes) != 0)
        return std::nullopt;

    return m;
}

LGZ22::Trapdoor LGZ22::auth(const Ciphertext &ct, const BIGNUM *y, const BIGNUM *xc,
                      const std::vector<const EC_POINT *> &testerKeys) const
{
    const size_t n = testerKeys.size();

    std::vector<Bn> roots;
    roots.reserve(n);
    for (size_t k = 0; k < n; k++)
        roots.push_back(H2(G_.exp(testerKeys[k], xc).get()));
    std::vector<Bn> A = G_.expandRootsProduct(roots);

    A[0] = G_.add(A[0].get(), H2(G_.exp(ct.c2.get(), xc).get()).get());

    Trapdoor td;
    for (size_t i = 0; i <= n; i++)
        td.td1.push_back(G_.expG(A[i].get()));
    td.td2 = G_.dup(y);
    return td;
}

Pt LGZ22::delta(const Ciphertext &ct, const Trapdoor &td, const BIGNUM *eta) const
{
    Pt gamma = G_.dup(td.td1[0].get());
    Bn etaPower = G_.fromU64(1);
    for (size_t k = 1; k < td.td1.size(); k++)
    {
        etaPower = G_.mulZp(etaPower.get(), eta);
        gamma = G_.mul(gamma.get(), G_.exp(td.td1[k].get(), etaPower.get()).get());
    }
    Pt c2y = G_.exp(ct.c2.get(), td.td2.get());
    return G_.div(ct.c4.get(), G_.mul(c2y.get(), gamma.get()).get());
}

bool LGZ22::test(const Ciphertext &cti, const Trapdoor &tdi,
                  const Ciphertext &ctj, const Trapdoor &tdj,
                  const BIGNUM *xtw, const EC_POINT *Xc) const
{
    if (tdi.td1.empty() || tdj.td1.empty())
        return false;
    Bn eta = H2(G_.exp(Xc, xtw).get());
    Pt deltaI = delta(cti, tdi, eta.get());
    Pt deltaJ = delta(ctj, tdj, eta.get());
    return G_.eq(deltaI.get(), deltaJ.get());
}

}
