#include "ModifiedPKEETFDA.h"

#include <set>

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace pkeet
{

ModifiedPKEETFDA::UserKey ModifiedPKEETFDA::userGen() const
{
    UserKey k;
    k.x = G_.randZpStar();
    k.y = G_.randZpStar();
    k.X = G_.expG(k.x.get());
    k.Y = G_.expG(k.y.get());
    return k;
}

ModifiedPKEETFDA::TesterKey ModifiedPKEETFDA::testerGen() const
{
    TesterKey k;
    k.xt = G_.randZpStar();
    k.Xt = G_.expG(k.xt.get());
    return k;
}

ModifiedPKEETFDA::Message ModifiedPKEETFDA::randomMessage() const
{
    Message M;
    if (RAND_bytes(M.data(), (int)M.size()) != 1)
        fatal("RAND_bytes");
    return M;
}

Bn ModifiedPKEETFDA::H1(const Message &M) const
{
    return G_.hashToZpStar(kDomainH1, {M});
}

Bn ModifiedPKEETFDA::H2(const EC_POINT *P) const
{
    return G_.hashToZpStar(kDomainH2, {G_.encodeCompressedOrZeroForIdentity(P)});
}

void ModifiedPKEETFDA::H3(const EC_POINT *C1, const EC_POINT *C2, const BIGNUM *C3, const EC_POINT *Z, uint8_t out[kC4Bytes]) const
{
    Group::shake256(kDomainH3,
                    {G_.encodeCompressedOrZeroForIdentity(C1),
                     G_.encodeCompressedOrZeroForIdentity(C2),
                     G_.encodeZp(C3),
                     G_.encodeCompressedOrZeroForIdentity(Z)},
                    out, kC4Bytes);
}

ModifiedPKEETFDA::RhoSigma ModifiedPKEETFDA::H4(const EC_POINT *Xt, const EC_POINT *D, const EC_POINT *W) const
{
    uint8_t h[kH4Bytes];
    Group::shake256(kDomainH4,
                    {G_.encodeCompressedOrZeroForIdentity(Xt),
                     G_.encodeCompressedOrZeroForIdentity(D),
                     G_.encodeCompressedOrZeroForIdentity(W)},
                    h, kH4Bytes);
    return {G_.wideBytesModP(h), G_.wideBytesModP(h + kWideHashBytes)};
}

ModifiedPKEETFDA::Ciphertext ModifiedPKEETFDA::encrypt(const Message &M, const EC_POINT *X, const EC_POINT *Y) const
{
    Bn r1 = G_.randZpStar();
    Bn r2 = G_.randZpStar();

    Ciphertext ct;
    ct.C1 = G_.expG(r1.get());
    ct.C2 = G_.expG(r2.get());

    Bn k = G_.mulZp(H1(M).get(), r1.get());
    ct.C3 = G_.mulZp(k.get(), H2(G_.exp(X, r1.get()).get()).get());

    uint8_t mask[kC4Bytes];
    H3(ct.C1.get(), ct.C2.get(), ct.C3.get(), G_.exp(Y, r2.get()).get(), mask);

    ZpBytes r1Bytes = G_.encodeZp(r1.get());
    ZpBytes r2Bytes = G_.encodeZp(r2.get());
    ct.C4.resize(kC4Bytes);
    for (size_t i = 0; i < kMessageBytes; i++)
        ct.C4[i] = M[i] ^ mask[i];
    for (size_t i = 0; i < kZpBytes; i++)
    {
        ct.C4[kMessageBytes + i]            = r1Bytes[i] ^ mask[kMessageBytes + i];
        ct.C4[kMessageBytes + kZpBytes + i] = r2Bytes[i] ^ mask[kMessageBytes + kZpBytes + i];
    }
    return ct;
}

std::optional<ModifiedPKEETFDA::DecryptionResult> ModifiedPKEETFDA::decryptWithTau(const Ciphertext &ct, const BIGNUM *x, const BIGNUM *y) const
{
    if (!ct.C1 || !ct.C2 || !ct.C3 || !G_.inZpStar(ct.C3.get()) || ct.C4.size() != kC4Bytes)
        return std::nullopt;

    Bn tau = H2(G_.exp(ct.C1.get(), x).get());
    Bn k = G_.mulZp(ct.C3.get(), G_.inv(tau.get()).get());

    uint8_t mask[kC4Bytes];
    H3(ct.C1.get(), ct.C2.get(), ct.C3.get(), G_.exp(ct.C2.get(), y).get(), mask);
    uint8_t mu[kC4Bytes];
    for (size_t i = 0; i < kC4Bytes; i++)
        mu[i] = ct.C4[i] ^ mask[i];

    DecryptionResult out;
    std::copy(mu, mu + kMessageBytes, out.M.begin());
    Bn r1 = G_.decodeZpUnreduced(mu + kMessageBytes);
    Bn r2 = G_.decodeZpUnreduced(mu + kMessageBytes + kZpBytes);

    if (!G_.inZpStar(r1.get()) || !G_.inZpStar(r2.get()))
        return std::nullopt;
    if (!G_.eq(ct.C1.get(), G_.expG(r1.get()).get()))
        return std::nullopt;
    if (!G_.eq(ct.C2.get(), G_.expG(r2.get()).get()))
        return std::nullopt;
    if (BN_cmp(k.get(), G_.mulZp(H1(out.M).get(), r1.get()).get()) != 0)
        return std::nullopt;

    out.tau = std::move(tau);
    return out;
}

std::optional<ModifiedPKEETFDA::Message> ModifiedPKEETFDA::decrypt(const Ciphertext &ct, const BIGNUM *x, const BIGNUM *y) const
{
    auto result = decryptWithTau(ct, x, y);
    if (!result)
        return std::nullopt;
    return result->M;
}

std::optional<ModifiedPKEETFDA::Trapdoor> ModifiedPKEETFDA::auth(const Ciphertext &ct, const UserKey &uk,
                                     const std::vector<const EC_POINT *> &testerKeys,
                                     AuthMode mode) const
{
    const size_t n = testerKeys.size();
    if (n == 0)
        return std::nullopt;

    std::set<PointBytes> seenTesterKeys;
    for (const EC_POINT *Xt : testerKeys)
    {
        if (G_.isIdentity(Xt) || !seenTesterKeys.insert(G_.encodeCompressedOrZeroForIdentity(Xt)).second)
            return std::nullopt;
    }

    Bn tau;
    if (mode == AuthMode::VerifyCiphertext)
    {
        auto dec = decryptWithTau(ct, uk.x.get(), uk.y.get());
        if (!dec)
            return std::nullopt;
        tau = std::move(dec->tau);
    }
    else
    {
        tau = H2(G_.exp(ct.C1.get(), uk.x.get()).get());
    }

    Bn rBar = G_.randZpStar();
    Trapdoor td;
    td.D = G_.expG(rBar.get());

    std::vector<Bn> rhos, values;
    std::set<ZpBytes> seenRhos;
    for (const EC_POINT *Xt : testerKeys)
    {
        RhoSigma rs = H4(Xt, td.D.get(), G_.exp(Xt, rBar.get()).get());
        if (!seenRhos.insert(G_.encodeZp(rs.rho.get())).second)
            return std::nullopt;
        values.push_back(G_.add(tau.get(), rs.sigma.get()));
        rhos.push_back(std::move(rs.rho));
    }

    td.a = G_.interpolateCoefficients(rhos, values);
    return td;
}

bool ModifiedPKEETFDA::wellFormedForTest(const Ciphertext &ct, const Trapdoor &td) const
{
    if (!td.D || G_.isIdentity(td.D.get()) || td.a.empty())
        return false;
    for (const Bn &coeff : td.a)
        if (!coeff || !G_.inZp(coeff.get()))
            return false;
    return ct.C1 && !G_.isIdentity(ct.C1.get()) && ct.C3 && G_.inZpStar(ct.C3.get());
}

std::optional<Bn> ModifiedPKEETFDA::recoverK(const Ciphertext &ct, const Trapdoor &td, const TesterKey &tester) const
{
    RhoSigma rs = H4(tester.Xt.get(), td.D.get(), G_.exp(td.D.get(), tester.xt.get()).get());
    Bn tau = G_.sub(G_.evaluatePolynomial(td.a, rs.rho.get()).get(), rs.sigma.get());
    if (BN_is_zero(tau.get()))
        return std::nullopt;
    return G_.mulZp(ct.C3.get(), G_.inv(tau.get()).get());
}

bool ModifiedPKEETFDA::test(const Ciphertext &cti, const Trapdoor &tdi,
                  const Ciphertext &ctj, const Trapdoor &tdj,
                  const TesterKey &tester) const
{
    if (!wellFormedForTest(cti, tdi) || !wellFormedForTest(ctj, tdj))
        return false;

    std::optional<Bn> ki = recoverK(cti, tdi, tester);
    std::optional<Bn> kj = recoverK(ctj, tdj, tester);
    if (!ki || !kj)
        return false;

    Bn exponent = G_.mulZp(kj->get(), G_.inv(ki->get()).get());
    return G_.eq(G_.exp(cti.C1.get(), exponent.get()).get(), ctj.C1.get());
}

}
