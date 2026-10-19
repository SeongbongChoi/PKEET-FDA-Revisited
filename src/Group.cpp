#include "Group.h"

#include <cstdio>
#include <cstdlib>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

namespace pkeet
{

uint64_t g_expCount = 0;

void fatal(const std::string &what)
{
    std::fprintf(stderr, "fatal: %s\n", what.c_str());
    std::abort();
}

#define OSSL_CHECK(expr) do { if (!(expr)) fatal(#expr); } while (0)

std::string Group::linkedOpenSSLVersion()
{
    return OpenSSL_version(OPENSSL_VERSION);
}

void Group::requireLinkedOpenSSL3()
{
    if (OpenSSL_version_num() < 0x30000000L || OPENSSL_VERSION_NUMBER < 0x30000000L)
        fatal("linked or compiled against OpenSSL < 3.0: " + linkedOpenSSLVersion());
}

Group::Group()
{
    grp_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ctx_ = BN_CTX_new();
    OSSL_CHECK(grp_ && ctx_);
    p_ = EC_GROUP_get0_order(grp_);
    g_ = EC_GROUP_get0_generator(grp_);
    OSSL_CHECK(p_ && g_ && BN_num_bits(p_) == 256);
    pMinus1_ = BN_dup(p_);
    OSSL_CHECK(pMinus1_ && BN_sub_word(pMinus1_, 1));
    mont_ = BN_MONT_CTX_new();
    OSSL_CHECK(mont_ && BN_MONT_CTX_set(mont_, p_, ctx_));
}

Group::~Group()
{
    BN_MONT_CTX_free(mont_);
    BN_free(pMinus1_);
    BN_CTX_free(ctx_);
    EC_GROUP_free(grp_);
}

Pt Group::expG(const BIGNUM *a) const
{
    return exp(g_, a);
}

Pt Group::exp(const EC_POINT *Q, const BIGNUM *a) const
{
    Pt r = newPoint();
    OSSL_CHECK(EC_POINT_mul(grp_, r.get(), NULL, Q, a, ctx_));
    ++g_expCount;
    return r;
}

Pt Group::newPoint() const
{
    Pt r(EC_POINT_new(grp_));
    OSSL_CHECK(r);
    return r;
}

Pt Group::identity() const
{
    Pt r = newPoint();
    OSSL_CHECK(EC_POINT_set_to_infinity(grp_, r.get()));
    return r;
}

Pt Group::dup(const EC_POINT *P) const
{
    Pt r(EC_POINT_dup(P, grp_));
    OSSL_CHECK(r);
    return r;
}

Pt Group::mul(const EC_POINT *P, const EC_POINT *Q) const
{
    Pt r = newPoint();
    OSSL_CHECK(EC_POINT_add(grp_, r.get(), P, Q, ctx_));
    return r;
}

Pt Group::div(const EC_POINT *P, const EC_POINT *Q) const
{
    Pt negQ = dup(Q);
    OSSL_CHECK(EC_POINT_invert(grp_, negQ.get(), ctx_));
    return mul(P, negQ.get());
}

bool Group::eq(const EC_POINT *P, const EC_POINT *Q) const
{
    int c = EC_POINT_cmp(grp_, P, Q, ctx_);
    OSSL_CHECK(c >= 0);
    return c == 0;
}

bool Group::isIdentity(const EC_POINT *P) const
{
    return EC_POINT_is_at_infinity(grp_, P) == 1;
}

PointBytes Group::encodeCompressedOrZeroForIdentity(const EC_POINT *P) const
{
    PointBytes out{};
    if (isIdentity(P))
        return out;
    size_t len = EC_POINT_point2oct(grp_, P, POINT_CONVERSION_COMPRESSED, out.data(), out.size(), ctx_);
    OSSL_CHECK(len == kPointBytes);
    return out;
}

Pt Group::decodeCompressed(const uint8_t *in, size_t len) const
{
    Pt r = newPoint();
    if (len != kPointBytes || EC_POINT_oct2point(grp_, r.get(), in, len, ctx_) != 1)
        return nullptr;
    return r;
}

Bn Group::newBn() const
{
    Bn r(BN_new());
    OSSL_CHECK(r);
    return r;
}

Bn Group::dup(const BIGNUM *a) const
{
    Bn r(BN_dup(a));
    OSSL_CHECK(r);
    return r;
}

Bn Group::fromU64(uint64_t v) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_set_word(r.get(), v));
    return r;
}

Bn Group::randZpStar() const
{
    Bn r = newBn();
    OSSL_CHECK(BN_priv_rand_range(r.get(), pMinus1_));
    OSSL_CHECK(BN_add_word(r.get(), 1));
    return r;
}

void Group::addInPlace(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const
{
    OSSL_CHECK(BN_mod_add_quick(r, a, b, p_));
}

void Group::subInPlace(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const
{
    OSSL_CHECK(BN_mod_sub_quick(r, a, b, p_));
}

void Group::montMulInPlace(BIGNUM *r, const BIGNUM *aMont, const BIGNUM *bMont) const
{
    OSSL_CHECK(BN_mod_mul_montgomery(r, aMont, bMont, mont_, ctx_));
}

Bn Group::toMont(const BIGNUM *a) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_to_montgomery(r.get(), a, mont_, ctx_));
    return r;
}

Bn Group::fromMont(const BIGNUM *aMont) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_from_montgomery(r.get(), aMont, mont_, ctx_));
    return r;
}

std::vector<Bn> Group::toMont(const std::vector<Bn> &as) const
{
    std::vector<Bn> out;
    out.reserve(as.size());
    for (const Bn &a : as)
        out.push_back(toMont(a.get()));
    return out;
}

std::vector<Bn> Group::fromMont(const std::vector<Bn> &asMont) const
{
    std::vector<Bn> out;
    out.reserve(asMont.size());
    for (const Bn &a : asMont)
        out.push_back(fromMont(a.get()));
    return out;
}

std::vector<Bn> Group::zeros(size_t count) const
{
    std::vector<Bn> out;
    out.reserve(count);
    for (size_t i = 0; i < count; i++)
        out.push_back(fromU64(0));
    return out;
}

std::vector<Bn> Group::expandRootsProductMont(const std::vector<Bn> &rootsMont) const
{
    std::vector<Bn> coeffs = zeros(rootsMont.size() + 1);
    Bn one = fromU64(1);
    coeffs[0] = toMont(one.get());
    Bn product = newBn();
    for (size_t degree = 0; degree < rootsMont.size(); degree++)
    {
        const BIGNUM *root = rootsMont[degree].get();
        for (size_t i = degree + 1; i >= 1; i--)
        {
            montMulInPlace(product.get(), root, coeffs[i].get());
            subInPlace(coeffs[i].get(), coeffs[i - 1].get(), product.get());
        }
        montMulInPlace(product.get(), root, coeffs[0].get());
        BN_zero(coeffs[0].get());
        subInPlace(coeffs[0].get(), coeffs[0].get(), product.get());
    }
    return coeffs;
}

std::vector<Bn> Group::expandRootsProduct(const std::vector<Bn> &roots) const
{
    return fromMont(expandRootsProductMont(toMont(roots)));
}

Bn Group::evaluatePolynomialMont(const std::vector<Bn> &coeffsMont, const BIGNUM *zMont) const
{
    Bn acc = dup(coeffsMont.back().get());
    for (size_t i = coeffsMont.size() - 1; i-- > 0;)
    {
        montMulInPlace(acc.get(), acc.get(), zMont);
        addInPlace(acc.get(), acc.get(), coeffsMont[i].get());
    }
    return acc;
}

Bn Group::evaluatePolynomial(const std::vector<Bn> &coeffs, const BIGNUM *z) const
{
    Bn zMont = toMont(z);
    return fromMont(evaluatePolynomialMont(toMont(coeffs), zMont.get()).get());
}

std::vector<Bn> Group::interpolateCoefficients(const std::vector<Bn> &xs, const std::vector<Bn> &ys) const
{
    const size_t n = xs.size();
    std::vector<Bn> xsMont = toMont(xs);
    std::vector<Bn> ysMont = toMont(ys);
    std::vector<Bn> vanishing = expandRootsProductMont(xsMont);

    std::vector<Bn> derivative = zeros(n);
    for (size_t i = 0; i < n; i++)
    {
        Bn multiplier = fromU64(i + 1);
        Bn multiplierMont = toMont(multiplier.get());
        montMulInPlace(derivative[i].get(), multiplierMont.get(), vanishing[i + 1].get());
    }

    std::vector<Bn> denominators;
    denominators.reserve(n);
    for (size_t k = 0; k < n; k++)
        denominators.push_back(evaluatePolynomialMont(derivative, xsMont[k].get()));

    std::vector<Bn> prefix = zeros(n);
    OSSL_CHECK(BN_copy(prefix[0].get(), denominators[0].get()));
    for (size_t k = 1; k < n; k++)
        montMulInPlace(prefix[k].get(), prefix[k - 1].get(), denominators[k].get());
    Bn running = toMont(inv(fromMont(prefix[n - 1].get()).get()).get());

    std::vector<Bn> scales = zeros(n);
    for (size_t k = n; k-- > 0;)
    {
        if (k == 0)
        {
            montMulInPlace(scales[0].get(), ysMont[0].get(), running.get());
            break;
        }
        montMulInPlace(scales[k].get(), running.get(), prefix[k - 1].get());
        montMulInPlace(scales[k].get(), scales[k].get(), ysMont[k].get());
        montMulInPlace(running.get(), running.get(), denominators[k].get());
    }

    std::vector<Bn> coeffs = zeros(n);
    std::vector<Bn> quotient = zeros(n);
    Bn product = newBn();
    for (size_t k = 0; k < n; k++)
    {
        OSSL_CHECK(BN_copy(quotient[n - 1].get(), vanishing[n].get()));
        for (size_t i = n - 1; i >= 1; i--)
        {
            montMulInPlace(product.get(), xsMont[k].get(), quotient[i].get());
            addInPlace(quotient[i - 1].get(), vanishing[i].get(), product.get());
        }
        for (size_t i = 0; i < n; i++)
        {
            montMulInPlace(product.get(), scales[k].get(), quotient[i].get());
            addInPlace(coeffs[i].get(), coeffs[i].get(), product.get());
        }
    }
    return fromMont(coeffs);
}

Bn Group::add(const BIGNUM *a, const BIGNUM *b) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_mod_add(r.get(), a, b, p_, ctx_));
    return r;
}

Bn Group::sub(const BIGNUM *a, const BIGNUM *b) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_mod_sub(r.get(), a, b, p_, ctx_));
    return r;
}

Bn Group::mulZp(const BIGNUM *a, const BIGNUM *b) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_mod_mul(r.get(), a, b, p_, ctx_));
    return r;
}

Bn Group::inv(const BIGNUM *a) const
{
    Bn r = newBn();
    OSSL_CHECK(BN_mod_inverse(r.get(), a, p_, ctx_));
    return r;
}

bool Group::inZp(const BIGNUM *a) const
{
    return !BN_is_negative(a) && BN_cmp(a, p_) < 0;
}

bool Group::inZpStar(const BIGNUM *a) const
{
    return inZp(a) && !BN_is_zero(a);
}

ZpBytes Group::encodeZp(const BIGNUM *a) const
{
    ZpBytes out{};
    OSSL_CHECK(!BN_is_negative(a) && BN_bn2binpad(a, out.data(), kZpBytes) == (int)kZpBytes);
    return out;
}

Bn Group::decodeZpUnreduced(const uint8_t *in32) const
{
    Bn r(BN_bin2bn(in32, kZpBytes, NULL));
    OSSL_CHECK(r);
    return r;
}

void Group::shake256(uint8_t domain, std::initializer_list<ByteView> in, uint8_t *out, size_t outlen)
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    OSSL_CHECK(md);
    OSSL_CHECK(EVP_DigestInit_ex(md, EVP_shake256(), NULL) == 1);
    OSSL_CHECK(EVP_DigestUpdate(md, &domain, 1) == 1);
    for (const ByteView &v : in)
        OSSL_CHECK(EVP_DigestUpdate(md, v.data, v.len) == 1);
    OSSL_CHECK(EVP_DigestFinalXOF(md, out, outlen) == 1);
    EVP_MD_CTX_free(md);
}

Bn Group::wideBytesModP(const uint8_t *in48) const
{
    Bn r(BN_bin2bn(in48, kWideHashBytes, NULL));
    OSSL_CHECK(r);
    OSSL_CHECK(BN_nnmod(r.get(), r.get(), p_, ctx_));
    return r;
}

Bn Group::hashToZp(uint8_t domain, std::initializer_list<ByteView> in) const
{
    uint8_t h[kWideHashBytes];
    shake256(domain, in, h, sizeof(h));
    return wideBytesModP(h);
}

Bn Group::hashToZpStar(uint8_t domain, std::initializer_list<ByteView> in) const
{
    uint8_t h[kWideHashBytes];
    shake256(domain, in, h, sizeof(h));
    Bn r(BN_bin2bn(h, sizeof(h), NULL));
    OSSL_CHECK(r);
    OSSL_CHECK(BN_nnmod(r.get(), r.get(), pMinus1_, ctx_));
    OSSL_CHECK(BN_add_word(r.get(), 1));
    return r;
}

}
