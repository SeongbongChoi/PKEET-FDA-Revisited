#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

#include <openssl/bn.h>
#include <openssl/ec.h>

namespace pkeet
{

constexpr size_t kPointBytes = 33;
constexpr size_t kZpBytes    = 32;
constexpr size_t kWideHashBytes = 48;

extern uint64_t g_expCount;

struct BnDeleter { void operator()(BIGNUM *b) const { BN_clear_free(b); } };
struct PtDeleter { void operator()(EC_POINT *p) const { EC_POINT_free(p); } };
using Bn = std::unique_ptr<BIGNUM, BnDeleter>;
using Pt = std::unique_ptr<EC_POINT, PtDeleter>;

using Bytes      = std::vector<uint8_t>;
using PointBytes = std::array<uint8_t, kPointBytes>;
using ZpBytes    = std::array<uint8_t, kZpBytes>;

struct ByteView
{
    const uint8_t *data;
    size_t len;

    ByteView(const uint8_t *d, size_t l) : data(d), len(l) {}
    template <size_t N>
    ByteView(const std::array<uint8_t, N> &a) : data(a.data()), len(N) {}
    ByteView(const Bytes &v) : data(v.data()), len(v.size()) {}
};

[[noreturn]] void fatal(const std::string &what);

template <typename TesterKeyT>
std::vector<const EC_POINT *> publicKeysOf(const std::vector<TesterKeyT> &testers)
{
    std::vector<const EC_POINT *> keys;
    keys.reserve(testers.size());
    for (const TesterKeyT &t : testers)
        keys.push_back(t.Xt.get());
    return keys;
}

class Group
{
public:
    Group();
    ~Group();
    Group(const Group &) = delete;
    Group &operator=(const Group &) = delete;

    static std::string linkedOpenSSLVersion();
    static void requireLinkedOpenSSL3();

    const BIGNUM   *order() const { return p_; }
    const EC_POINT *generator() const { return g_; }

    Pt expG(const BIGNUM *a) const;
    Pt exp(const EC_POINT *Q, const BIGNUM *a) const;

    Pt   newPoint() const;
    Pt   identity() const;
    Pt   dup(const EC_POINT *P) const;
    Pt   mul(const EC_POINT *P, const EC_POINT *Q) const;
    Pt   div(const EC_POINT *P, const EC_POINT *Q) const;
    bool eq(const EC_POINT *P, const EC_POINT *Q) const;
    bool isIdentity(const EC_POINT *P) const;

    PointBytes encodeCompressedOrZeroForIdentity(const EC_POINT *P) const;
    Pt decodeCompressed(const uint8_t *in, size_t len) const;

    Bn      newBn() const;
    Bn      dup(const BIGNUM *a) const;
    Bn      fromU64(uint64_t v) const;
    Bn      randZpStar() const;
    std::vector<Bn> expandRootsProduct(const std::vector<Bn> &roots) const;
    Bn      evaluatePolynomial(const std::vector<Bn> &coeffs, const BIGNUM *z) const;
    std::vector<Bn> interpolateCoefficients(const std::vector<Bn> &xs, const std::vector<Bn> &ys) const;
    Bn      add(const BIGNUM *a, const BIGNUM *b) const;
    Bn      sub(const BIGNUM *a, const BIGNUM *b) const;
    Bn      mulZp(const BIGNUM *a, const BIGNUM *b) const;
    Bn      inv(const BIGNUM *a) const;
    bool    inZp(const BIGNUM *a) const;
    bool    inZpStar(const BIGNUM *a) const;
    ZpBytes encodeZp(const BIGNUM *a) const;
    Bn      decodeZpUnreduced(const uint8_t *in32) const;

    static void shake256(uint8_t domain, std::initializer_list<ByteView> in, uint8_t *out, size_t outlen);
    Bn hashToZp(uint8_t domain, std::initializer_list<ByteView> in) const;
    Bn hashToZpStar(uint8_t domain, std::initializer_list<ByteView> in) const;
    Bn wideBytesModP(const uint8_t *in48) const;

private:
    std::vector<Bn> zeros(size_t count) const;
    Bn   toMont(const BIGNUM *a) const;
    Bn   fromMont(const BIGNUM *aMont) const;
    std::vector<Bn> toMont(const std::vector<Bn> &as) const;
    std::vector<Bn> fromMont(const std::vector<Bn> &asMont) const;
    void montMulInPlace(BIGNUM *r, const BIGNUM *aMont, const BIGNUM *bMont) const;
    void addInPlace(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const;
    void subInPlace(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) const;
    std::vector<Bn> expandRootsProductMont(const std::vector<Bn> &rootsMont) const;
    Bn   evaluatePolynomialMont(const std::vector<Bn> &coeffsMont, const BIGNUM *zMont) const;

    EC_GROUP       *grp_;
    BN_CTX         *ctx_;
    const BIGNUM   *p_;
    BIGNUM         *pMinus1_;
    BN_MONT_CTX    *mont_;
    const EC_POINT *g_;
};

}
