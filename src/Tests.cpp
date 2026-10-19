#include <cstdio>
#include <cstring>
#include <functional>
#include <string>

#include <openssl/rand.h>

#include "Group.h"
#include "LGZ22.h"
#include "ModifiedPKEETFDA.h"

using namespace pkeet;

static int g_failures = 0;
static int g_passes = 0;

static void check(bool ok, const std::string &what)
{
    if (ok)
    {
        ++g_passes;
        std::printf("  [PASS] %s\n", what.c_str());
    }
    else
    {
        ++g_failures;
        std::printf("  [FAIL] %s\n", what.c_str());
    }
}

template <typename F>
static uint64_t expsUsedBy(F &&op)
{
    uint64_t before = g_expCount;
    op();
    return g_expCount - before;
}

static LGZ22::Ciphertext copyOf(const Group &G, const LGZ22::Ciphertext &ct)
{
    LGZ22::Ciphertext out;
    out.c1 = G.dup(ct.c1.get());
    out.c2 = G.dup(ct.c2.get());
    out.c3 = ct.c3;
    out.c4 = G.dup(ct.c4.get());
    out.c5 = ct.c5;
    return out;
}

static ModifiedPKEETFDA::Ciphertext copyOf(const Group &G, const ModifiedPKEETFDA::Ciphertext &ct)
{
    ModifiedPKEETFDA::Ciphertext out;
    out.C1 = G.dup(ct.C1.get());
    out.C2 = G.dup(ct.C2.get());
    out.C3 = G.dup(ct.C3.get());
    out.C4 = ct.C4;
    return out;
}

static bool sameCiphertext(const Group &G, const LGZ22::Ciphertext &a, const LGZ22::Ciphertext &b)
{
    return G.eq(a.c1.get(), b.c1.get()) && G.eq(a.c2.get(), b.c2.get()) && a.c3 == b.c3
        && G.eq(a.c4.get(), b.c4.get()) && a.c5 == b.c5;
}

static void testGroupEncoding(const Group &G)
{
    std::printf("\n=== Group / encoding ===\n");
    Bn a = G.randZpStar();
    Pt P = G.expG(a.get());
    PointBytes enc = G.encodeCompressedOrZeroForIdentity(P.get());
    Pt back = G.decodeCompressed(enc.data(), enc.size());
    check(back && G.eq(P.get(), back.get()) && (enc[0] == 0x02 || enc[0] == 0x03),
          "point encodes to 33-byte compressed form and round-trips");
    check(G.encodeZp(a.get()).size() == 32, "Zp element encodes to 32 bytes");

    bool allInRange = true;
    for (int i = 0; i < 1000; i++)
    {
        uint8_t in[4];
        std::memcpy(in, &i, 4);
        Bn h = G.hashToZpStar(0x7f, {ByteView(in, 4)});
        Bn z = G.hashToZp(0x7f, {ByteView(in, 4)});
        allInRange &= G.inZpStar(h.get()) && G.inZp(z.get());
    }
    check(allInRange, "hashToZpStar lands in [1,p-1] and hashToZp in [0,p-1] (1000 inputs)");

    uint8_t x[1] = {0x00}, d1[32], d2[32];
    Group::shake256(0x01, {ByteView(x, 1)}, d1, 32);
    Group::shake256(0x02, {ByteView(x, 1)}, d2, 32);
    check(std::memcmp(d1, d2, 32) != 0, "distinct domain bytes give distinct SHAKE256 outputs");

    uint64_t baseG = expsUsedBy([&] { G.expG(a.get()); });
    uint64_t baseRandomPoint = expsUsedBy([&] { G.exp(P.get(), a.get()); });
    check(baseG == 1 && baseRandomPoint == 1, "each EC_POINT_mul wrapper call counts as exactly one Exp");
    check(G.eq(G.expG(a.get()).get(), G.exp(G.generator(), a.get()).get()), "g^a is computed as EC_POINT_mul(G, r, NULL, g, a)");
}

static void testLGZ22(const Group &G)
{
    std::printf("\n=== LGZ22: correctness ===\n");
    LGZ22 S(G);
    LGZ22::ServerKey server = S.serverGen();
    LGZ22::UserKey alice = S.userGen();
    LGZ22::UserKey bob = S.userGen();

    bool roundTrip = true;
    for (int t = 0; t < 50; t++)
    {
        Bn m = S.randomMessage();
        LGZ22::Ciphertext ct = S.encrypt(m.get(), alice.X.get(), alice.Y.get(), server.Xc.get());
        auto dec = S.decrypt(ct, alice.x.get());
        roundTrip &= dec && BN_cmp(dec->get(), m.get()) == 0;
    }
    check(roundTrip, "Dec(Enc(m)) = m for 50 random m in Zp*");

    Bn m = S.randomMessage();
    LGZ22::Ciphertext ct = S.encrypt(m.get(), alice.X.get(), alice.Y.get(), server.Xc.get());
    check(!S.decrypt(ct, bob.x.get()), "Dec with another user's key returns bottom");

    {
        auto bad = copyOf(G, ct); bad.c3[5] ^= 1;
        check(!S.decrypt(bad, alice.x.get()), "Dec rejects modified c3");
    }
    {
        auto bad = copyOf(G, ct); bad.c5[0] ^= 1;
        check(!S.decrypt(bad, alice.x.get()), "Dec rejects modified c5");
    }
    {
        auto bad = copyOf(G, ct); bad.c1 = G.expG(G.randZpStar().get());
        check(!S.decrypt(bad, alice.x.get()), "Dec rejects replaced c1");
    }
    {
        auto bad = copyOf(G, ct); bad.c2 = G.expG(G.randZpStar().get());
        check(!S.decrypt(bad, alice.x.get()), "Dec rejects replaced c2 (c5 binds c2)");
    }
    {
        auto bad = copyOf(G, ct); bad.c4 = G.mul(bad.c4.get(), G.generator());
        check(!S.decrypt(bad, alice.x.get()), "Dec rejects modified c4 (c5 binds c4)");
    }

    check(expsUsedBy([&] { S.encrypt(m.get(), alice.X.get(), alice.Y.get(), server.Xc.get()); }) == 6, "Enc uses 6 Exp");
    check(expsUsedBy([&] { S.decrypt(ct, alice.x.get()); }) == 2, "Dec uses 2 Exp");

    for (size_t n : {1, 2, 5, 10})
    {
        std::vector<LGZ22::TesterKey> testers;
        for (size_t k = 0; k < n; k++)
            testers.push_back(S.testerGen());
        auto keys = publicKeysOf(testers);
        LGZ22::TesterKey outsider = S.testerGen();

        Bn m2 = S.randomMessage();
        auto ctA = S.encrypt(m.get(), alice.X.get(), alice.Y.get(), server.Xc.get());
        auto ctB = S.encrypt(m.get(), alice.X.get(), alice.Y.get(), server.Xc.get());
        auto ctC = S.encrypt(m2.get(), alice.X.get(), alice.Y.get(), server.Xc.get());
        auto ctBob = S.encrypt(m.get(), bob.X.get(), bob.Y.get(), server.Xc.get());

        LGZ22::Trapdoor tdA, tdB, tdC, tdBob;
        uint64_t authExps = expsUsedBy([&] { tdA = S.auth(ctA, alice.y.get(), server.xc.get(), keys); });
        tdB = S.auth(ctB, alice.y.get(), server.xc.get(), keys);
        tdC = S.auth(ctC, alice.y.get(), server.xc.get(), keys);
        tdBob = S.auth(ctBob, bob.y.get(), server.xc.get(), keys);

        bool same = true, diff = true, crossUser = true;
        for (const auto &w : testers)
        {
            same &= S.test(ctA, tdA, ctB, tdB, w.xt.get(), server.Xc.get());
            diff &= !S.test(ctA, tdA, ctC, tdC, w.xt.get(), server.Xc.get());
            crossUser &= S.test(ctA, tdA, ctBob, tdBob, w.xt.get(), server.Xc.get());
        }
        std::string tag = " (n=" + std::to_string(n) + ")";
        check(same, "Test = 1 for equal messages, every authorized tester" + tag);
        check(diff, "Test = 0 for different messages, every authorized tester" + tag);
        check(crossUser, "Test = 1 for equal messages across two users" + tag);
        std::vector<LGZ22::TesterKey> otherTesters;
        for (size_t k = 0; k < n; k++)
            otherTesters.push_back(S.testerGen());
        LGZ22::Trapdoor tdBOtherSet = S.auth(ctB, alice.y.get(), server.xc.get(), publicKeysOf(otherTesters));
        check(!S.test(ctA, tdA, ctB, tdBOtherSet, outsider.xt.get(), server.Xc.get()),
              "Test = 0 for an unauthorized tester when TD_i, TD_j name different tester sets" + tag);

        Bn zero = G.fromU64(0);
        bool outsiderLearnsEquality = S.test(ctA, tdA, ctB, tdB, outsider.xt.get(), server.Xc.get())
                                   && !S.test(ctA, tdA, ctC, tdC, outsider.xt.get(), server.Xc.get());
        bool keylessLearnsEquality = G.eq(S.delta(ctA, tdA, zero.get()).get(), S.delta(ctB, tdB, zero.get()).get())
                                  && !G.eq(S.delta(ctA, tdA, zero.get()).get(), S.delta(ctC, tdC, zero.get()).get());
        check(outsiderLearnsEquality,
              "LGZ22 testability violation reproduced: unauthorized tester gets the correct equality result when TD_i, TD_j name the same tester set" + tag);
        check(keylessLearnsEquality,
              "LGZ22 testability violation reproduced: eta = 0 (no tester key) gives the correct equality result for the same tester set" + tag);
        check(tdA.td1.size() == n + 1 && G.eq(tdA.td1[n].get(), G.generator()), "td1 has n+1 entries and g^A_n = g" + tag);
        check(authExps == 2 * n + 2, "Aut uses 2n+2 Exp" + tag);
        uint64_t testExps = expsUsedBy([&] { S.test(ctA, tdA, ctB, tdB, testers[0].xt.get(), server.Xc.get()); });
        check(testExps == 2 * n + 3, "Test uses 2n+3 Exp" + tag);
    }
}

static LGZ22::Ciphertext adversaryEncryptLGZ22(const Group &G, const LGZ22 &S, const EC_POINT *X,
                                           const BIGNUM *m, const BIGNUM *u, Pt c2, Pt c4)
{
    LGZ22::Ciphertext ct;
    ct.c1 = G.expG(u);
    ct.c2 = std::move(c2);
    ct.c4 = std::move(c4);

    uint8_t mu[LGZ22::kMessageAndUBytes];
    ZpBytes mBytes = G.encodeZp(m), uBytes = G.encodeZp(u);
    std::copy(mBytes.begin(), mBytes.end(), mu);
    std::copy(uBytes.begin(), uBytes.end(), mu + kZpBytes);

    uint8_t mask[LGZ22::kMessageAndUBytes];
    S.H1(G.exp(X, u).get(), mask);
    for (size_t i = 0; i < LGZ22::kMessageAndUBytes; i++)
        ct.c3[i] = mu[i] ^ mask[i];
    S.H3(ct, mu, ct.c5.data());
    return ct;
}

static int coinFlip()
{
    uint8_t coin;
    if (RAND_bytes(&coin, 1) != 1)
        fatal("RAND_bytes");
    return coin & 1;
}

static bool sameCiphertext(const Group &G, const ModifiedPKEETFDA::Ciphertext &a, const ModifiedPKEETFDA::Ciphertext &b)
{
    return G.eq(a.C1.get(), b.C1.get()) && G.eq(a.C2.get(), b.C2.get())
        && BN_cmp(a.C3.get(), b.C3.get()) == 0 && a.C4 == b.C4;
}

constexpr int kAttackTrials = 1000;

static void attackLGZ22A(const Group &G)
{
    std::printf("\n=== Attack A (LGZ22): one Aut query on a forged ciphertext, adversary's own tester key ===\n");
    LGZ22 S(G);

    for (size_t n : {1, 5})
        for (bool reuseC4 : {false, true})
        {
            int correct = 0, forgedDecrypts = 0, refusals = 0;
            for (int t = 0; t < kAttackTrials; t++)
            {
                LGZ22::ServerKey server = S.serverGen();
                LGZ22::UserKey user = S.userGen();
                LGZ22::TesterKey adversaryTester = S.testerGen();
                std::vector<LGZ22::TesterKey> honestTesters;
                for (size_t k = 1; k < n; k++)
                    honestTesters.push_back(S.testerGen());
                std::vector<const EC_POINT *> testerList = publicKeysOf(honestTesters);
                testerList.insert(testerList.begin(), adversaryTester.Xt.get());

                Bn m0 = S.randomMessage(), m1 = S.randomMessage();
                int b = coinFlip();
                LGZ22::Ciphertext challenge = S.encrypt(b ? m1.get() : m0.get(), user.X.get(), user.Y.get(), server.Xc.get());

                Bn forgedU = G.randZpStar();
                while (G.eq(G.expG(forgedU.get()).get(), challenge.c1.get()))
                    forgedU = G.randZpStar();
                Bn forgedM = S.randomMessage();
                Pt forgedC4 = reuseC4 ? G.dup(challenge.c4.get()) : G.expG(G.randZpStar().get());
                LGZ22::Ciphertext forged = adversaryEncryptLGZ22(G, S, user.X.get(), forgedM.get(), forgedU.get(),
                                                             G.dup(challenge.c2.get()), std::move(forgedC4));
                if (sameCiphertext(G, forged, challenge))
                {
                    ++refusals;
                    continue;
                }

                auto dec = S.decrypt(forged, user.x.get());
                forgedDecrypts += dec && BN_cmp(dec->get(), forgedM.get()) == 0;

                LGZ22::Trapdoor forgedTd = S.auth(forged, user.y.get(), server.xc.get(), testerList);
                Bn eta = S.H2(G.exp(server.Xc.get(), adversaryTester.xt.get()).get());
                Pt W = S.delta(challenge, forgedTd, eta.get());
                int guess = G.eq(W.get(), G.expG(m0.get()).get()) ? 0 : 1;
                correct += guess == b;
            }

            std::string tag = " (n=" + std::to_string(n) + (reuseC4 ? ", variant: c4bar = c4*" : ", c4bar random") + ")";
            std::printf("  n=%zu %-22s: b guessed %d/%d, forged ct passes Dec %d/%d, oracle refusals %d\n",
                        n, reuseC4 ? "variant c4bar = c4*" : "c4bar random", correct, kAttackTrials, forgedDecrypts, kAttackTrials, refusals);
            check(refusals == 0, "A: forged ciphertext always differs from CT*" + tag);
            check(forgedDecrypts == kAttackTrials, "A: forged ciphertext passes Dec" + tag);
            check(correct == kAttackTrials, "A: adversary guesses b in 1000/1000 trials" + tag);
        }
}

static void attackLGZ22B(const Group &G)
{
    std::printf("\n=== Attack B (LGZ22): two Aut queries, no tester key, g^{A0} comparison ===\n");
    LGZ22 S(G);

    for (size_t n : {1, 5})
    {
        int correct = 0, recoveredExactly = 0, forgedDecrypts = 0, refusals = 0;
        for (int t = 0; t < kAttackTrials; t++)
        {
            LGZ22::ServerKey server = S.serverGen();
            LGZ22::UserKey user = S.userGen();
            std::vector<LGZ22::TesterKey> honestTesters;
            for (size_t k = 0; k < n; k++)
                honestTesters.push_back(S.testerGen());
            auto honestKeys = publicKeysOf(honestTesters);

            Bn m0 = S.randomMessage(), m1 = S.randomMessage();
            int b = coinFlip();
            LGZ22::Ciphertext challenge = S.encrypt(b ? m1.get() : m0.get(), user.X.get(), user.Y.get(), server.Xc.get());

            auto autOracle = [&](const LGZ22::Ciphertext &ct) -> std::optional<LGZ22::Trapdoor> {
                if (sameCiphertext(G, ct, challenge)) { ++refusals; return std::nullopt; }
                return S.auth(ct, user.y.get(), server.xc.get(), honestKeys);
            };

            Bn ownM = S.randomMessage(), ownU = G.randZpStar(), ownV = G.randZpStar();
            Bn ownH2 = S.H2(G.exp(server.Xc.get(), ownV.get()).get());
            Pt ownC4 = G.mul(G.exp(user.Y.get(), ownV.get()).get(),
                             G.expG(G.add(ownH2.get(), ownM.get()).get()).get());
            LGZ22::Ciphertext ownCt = adversaryEncryptLGZ22(G, S, user.X.get(), ownM.get(), ownU.get(),
                                                        G.expG(ownV.get()), std::move(ownC4));
            auto ownTd = autOracle(ownCt);
            Pt gToProductOfNegatedRoots = G.div(ownTd->td1[0].get(), G.expG(ownH2.get()).get());
            const BIGNUM *leakedY = ownTd->td2.get();

            Bn forgedM = S.randomMessage(), forgedU = G.randZpStar();
            LGZ22::Ciphertext forged = adversaryEncryptLGZ22(G, S, user.X.get(), forgedM.get(), forgedU.get(),
                                                         G.dup(challenge.c2.get()), G.dup(challenge.c4.get()));
            auto forgedDec = S.decrypt(forged, user.x.get());
            forgedDecrypts += forgedDec && BN_cmp(forgedDec->get(), forgedM.get()) == 0;
            auto forgedTd = autOracle(forged);

            Pt gToChallengeH2 = G.div(forgedTd->td1[0].get(), gToProductOfNegatedRoots.get());
            Pt c2y = G.exp(challenge.c2.get(), leakedY);
            Pt gToMb = G.div(challenge.c4.get(), G.mul(c2y.get(), gToChallengeH2.get()).get());

            int guess = G.eq(gToMb.get(), G.expG(m0.get()).get()) ? 0 : 1;
            correct += guess == b;
            recoveredExactly += G.eq(gToMb.get(), G.expG(b ? m1.get() : m0.get()).get());
        }

        std::string tag = " (n=" + std::to_string(n) + ")";
        std::printf("  n=%zu: b guessed %d/%d, g^{m_b} recovered %d/%d, forged ct passes Dec %d/%d, oracle refusals %d\n",
                    n, correct, kAttackTrials, recoveredExactly, kAttackTrials, forgedDecrypts, kAttackTrials, refusals);
        check(refusals == 0, "B: adversary never queries CT*" + tag);
        check(forgedDecrypts == kAttackTrials, "B: forged ciphertext passes Dec" + tag);
        check(recoveredExactly == kAttackTrials, "B: adversary recovers g^{m_b} exactly" + tag);
        check(correct == kAttackTrials, "B: adversary guesses b in 1000/1000 trials" + tag);
    }
}

static void attackLGZ22C(const Group &G)
{
    std::printf("\n=== Attack C (LGZ22, Type-III): Aut on CT* and on an honest encryption of m0, no tester secret key ===\n");
    LGZ22 S(G);

    for (size_t n : {1, 5})
    {
        int correct = 0;
        for (int t = 0; t < kAttackTrials; t++)
        {
            LGZ22::ServerKey server = S.serverGen();
            LGZ22::UserKey user = S.userGen();
            std::vector<LGZ22::TesterKey> honestTesters;
            for (size_t k = 0; k < n; k++)
                honestTesters.push_back(S.testerGen());
            auto honestKeys = publicKeysOf(honestTesters);

            Bn m0 = S.randomMessage(), m1 = S.randomMessage();
            int b = coinFlip();
            LGZ22::Ciphertext challenge = S.encrypt(b ? m1.get() : m0.get(), user.X.get(), user.Y.get(), server.Xc.get());
            LGZ22::Ciphertext ofM0 = S.encrypt(m0.get(), user.X.get(), user.Y.get(), server.Xc.get());

            LGZ22::Trapdoor challengeTd = S.auth(challenge, user.y.get(), server.xc.get(), honestKeys);
            LGZ22::Trapdoor ofM0Td = S.auth(ofM0, user.y.get(), server.xc.get(), honestKeys);

            Bn zero = G.fromU64(0);
            int guess = G.eq(S.delta(challenge, challengeTd, zero.get()).get(), S.delta(ofM0, ofM0Td, zero.get()).get()) ? 0 : 1;
            correct += guess == b;
        }
        std::string tag = " (n=" + std::to_string(n) + ")";
        std::printf("  n=%zu: b guessed %d/%d\n", n, correct, kAttackTrials);
        check(correct == kAttackTrials, "C: Type-III adversary guesses b in 1000/1000 trials" + tag);
    }
}

static void testModifiedPKEETFDA(const Group &G)
{
    std::printf("\n=== ModifiedPKEETFDA: correctness ===\n");
    ModifiedPKEETFDA S(G);
    ModifiedPKEETFDA::UserKey alice = S.userGen();
    ModifiedPKEETFDA::UserKey bob = S.userGen();

    bool roundTrip = true;
    for (int t = 0; t < 50; t++)
    {
        ModifiedPKEETFDA::Message M = S.randomMessage();
        auto dec = S.decrypt(S.encrypt(M, alice.X.get(), alice.Y.get()), alice.x.get(), alice.y.get());
        roundTrip &= dec && *dec == M;
    }
    check(roundTrip, "Dec(Enc(M)) = M for 50 random M in {0,1}^256");

    ModifiedPKEETFDA::Message M = S.randomMessage();
    ModifiedPKEETFDA::Ciphertext ct = S.encrypt(M, alice.X.get(), alice.Y.get());
    check(!S.decrypt(ct, bob.x.get(), bob.y.get()), "Dec with another user's key returns bottom");
    check(ModifiedPKEETFDA::ciphertextBytes() == 2 * 33 + 32 + 96, "ciphertext is 2|G| + |Zp| + 768 bits");

    auto rejects = [&](const std::string &what, const std::function<void(ModifiedPKEETFDA::Ciphertext &)> &tamper) {
        ModifiedPKEETFDA::Ciphertext bad = copyOf(G, ct);
        tamper(bad);
        check(!S.decrypt(bad, alice.x.get(), alice.y.get()), "Dec rejects " + what);
        check(!S.auth(bad, alice, {S.testerGen().Xt.get()}), "Aut rejects " + what);
    };
    rejects("replaced C1", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C1 = G.expG(G.randZpStar().get()); });
    rejects("replaced C2", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C2 = G.expG(G.randZpStar().get()); });
    rejects("C3 + 1", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C3 = G.add(c.C3.get(), G.fromU64(1).get()); });
    rejects("C3 = 0", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C3 = G.fromU64(0); });
    rejects("C3 = p", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C3 = G.dup(G.order()); });
    rejects("flipped bit in C4 message part", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C4[0] ^= 1; });
    rejects("flipped bit in C4 r1 part", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C4[ModifiedPKEETFDA::kMessageBytes + 31] ^= 1; });
    rejects("flipped bit in C4 r2 part", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C4[ModifiedPKEETFDA::kMessageBytes + kZpBytes + 31] ^= 1; });
    rejects("truncated C4", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C4.pop_back(); });
    rejects("identity C1", [&](ModifiedPKEETFDA::Ciphertext &c) { c.C1 = G.identity(); });

    check(expsUsedBy([&] { S.encrypt(M, alice.X.get(), alice.Y.get()); }) == 4, "Enc uses 4 Exp");
    check(expsUsedBy([&] { S.decrypt(ct, alice.x.get(), alice.y.get()); }) == 4, "Dec uses 4 Exp");

    {
        ModifiedPKEETFDA::TesterKey t1 = S.testerGen();
        Pt identity = G.identity();
        check(!S.auth(ct, alice, {}), "Aut rejects an empty tester set");
        check(!S.auth(ct, alice, {t1.Xt.get(), t1.Xt.get()}), "Aut rejects duplicate tester keys");
        check(!S.auth(ct, alice, {t1.Xt.get(), identity.get()}), "Aut rejects an identity tester key");
    }

    for (size_t n : {1, 2, 5, 10})
    {
        std::vector<ModifiedPKEETFDA::TesterKey> testers;
        for (size_t k = 0; k < n; k++)
            testers.push_back(S.testerGen());
        auto keys = publicKeysOf(testers);
        ModifiedPKEETFDA::TesterKey outsider = S.testerGen();
        std::string tag = " (n=" + std::to_string(n) + ")";

        ModifiedPKEETFDA::Message M2 = S.randomMessage();
        ModifiedPKEETFDA::Ciphertext ctA = S.encrypt(M, alice.X.get(), alice.Y.get());
        ModifiedPKEETFDA::Ciphertext ctB = S.encrypt(M, alice.X.get(), alice.Y.get());
        ModifiedPKEETFDA::Ciphertext ctC = S.encrypt(M2, alice.X.get(), alice.Y.get());
        ModifiedPKEETFDA::Ciphertext ctBob = S.encrypt(M, bob.X.get(), bob.Y.get());

        for (ModifiedPKEETFDA::AuthMode mode : {ModifiedPKEETFDA::AuthMode::VerifyCiphertext, ModifiedPKEETFDA::AuthMode::SkipVerification})
        {
            std::string modeTag = std::string(mode == ModifiedPKEETFDA::AuthMode::VerifyCiphertext ? " [verify]" : " [skip-verify]") + tag;
            std::optional<ModifiedPKEETFDA::Trapdoor> tdA;
            uint64_t authExps = expsUsedBy([&] { tdA = S.auth(ctA, alice, keys, mode); });
            auto tdB = S.auth(ctB, alice, keys, mode);
            auto tdC = S.auth(ctC, alice, keys, mode);
            auto tdBob = S.auth(ctBob, bob, keys, mode);
            check(tdA && tdB && tdC && tdBob && tdA->a.size() == n, "Aut outputs TD = (D, a_0..a_{n-1})" + modeTag);

            bool same = true, diff = true, crossUser = true;
            for (const auto &w : testers)
            {
                same &= S.test(ctA, *tdA, ctB, *tdB, w);
                diff &= !S.test(ctA, *tdA, ctC, *tdC, w);
                crossUser &= S.test(ctA, *tdA, ctBob, *tdBob, w);
            }
            check(same, "Test = 1 for equal messages, every authorized tester" + modeTag);
            check(diff, "Test = 0 for different messages, every authorized tester" + modeTag);
            check(crossUser, "Test = 1 for equal messages across two users" + modeTag);
            check(!S.test(ctA, *tdA, ctB, *tdB, outsider), "Test = 0 for an unauthorized tester" + modeTag);
            uint64_t expected = mode == ModifiedPKEETFDA::AuthMode::VerifyCiphertext ? n + 5 : n + 2;
            check(authExps == expected, std::string("Aut uses ") + (mode == ModifiedPKEETFDA::AuthMode::VerifyCiphertext ? "n+5" : "n+2") + " Exp" + modeTag);
            uint64_t testExps = expsUsedBy([&] { S.test(ctA, *tdA, ctB, *tdB, testers[0]); });
            check(testExps == 3, "Test uses 3 Exp" + modeTag);

            bool interpolates = true;
            for (const auto &w : testers)
            {
                ModifiedPKEETFDA::RhoSigma rs = S.H4(w.Xt.get(), tdA->D.get(), G.exp(tdA->D.get(), w.xt.get()).get());
                Bn tau = S.H2(G.exp(ctA.C1.get(), alice.x.get()).get());
                interpolates &= BN_cmp(G.evaluatePolynomial(tdA->a, rs.rho.get()).get(),
                                       G.add(tau.get(), rs.sigma.get()).get()) == 0;
            }
            check(interpolates, "P(rho_k) = tau + sigma_k for every authorized tester" + modeTag);
        }

        auto tdA = S.auth(ctA, alice, keys);
        auto tdB = S.auth(ctB, alice, keys);
        const ModifiedPKEETFDA::TesterKey &w = testers[0];
        auto malformed = [&](const std::string &what, const std::function<void(ModifiedPKEETFDA::Ciphertext &, ModifiedPKEETFDA::Trapdoor &)> &tamper) {
            ModifiedPKEETFDA::Ciphertext c = copyOf(G, ctA);
            ModifiedPKEETFDA::Trapdoor td;
            td.D = G.dup(tdA->D.get());
            for (const Bn &coeff : tdA->a)
                td.a.push_back(G.dup(coeff.get()));
            tamper(c, td);
            check(!S.test(c, td, ctB, *tdB, w) && !S.test(ctB, *tdB, c, td, w), "Test = 0 when " + what + tag);
        };
        malformed("D is the identity", [&](ModifiedPKEETFDA::Ciphertext &, ModifiedPKEETFDA::Trapdoor &td) { td.D = G.identity(); });
        malformed("TD has no coefficients", [&](ModifiedPKEETFDA::Ciphertext &, ModifiedPKEETFDA::Trapdoor &td) { td.a.clear(); });
        malformed("a coefficient equals p", [&](ModifiedPKEETFDA::Ciphertext &, ModifiedPKEETFDA::Trapdoor &td) { td.a[0] = G.dup(G.order()); });
        malformed("C1 is the identity", [&](ModifiedPKEETFDA::Ciphertext &c, ModifiedPKEETFDA::Trapdoor &) { c.C1 = G.identity(); });
        malformed("C3 = 0", [&](ModifiedPKEETFDA::Ciphertext &c, ModifiedPKEETFDA::Trapdoor &) { c.C3 = G.fromU64(0); });
        malformed("C3 = p", [&](ModifiedPKEETFDA::Ciphertext &c, ModifiedPKEETFDA::Trapdoor &) { c.C3 = G.dup(G.order()); });
    }
}

static void attackModifiedPKEETFDAA(const Group &G)
{
    std::printf("\n=== Attack A on ModifiedPKEETFDA: forged ciphertext with (C2*, C4*), adversary's own tester key ===\n");
    ModifiedPKEETFDA S(G);

    for (size_t n : {1, 5})
    {
        int correct = 0, autRejected = 0, decRejected = 0, refusals = 0;
        for (int t = 0; t < kAttackTrials; t++)
        {
            ModifiedPKEETFDA::UserKey user = S.userGen();
            ModifiedPKEETFDA::TesterKey adversaryTester = S.testerGen();
            std::vector<ModifiedPKEETFDA::TesterKey> honestTesters;
            for (size_t k = 1; k < n; k++)
                honestTesters.push_back(S.testerGen());
            std::vector<const EC_POINT *> testerList = publicKeysOf(honestTesters);
            testerList.insert(testerList.begin(), adversaryTester.Xt.get());

            ModifiedPKEETFDA::Message M0 = S.randomMessage(), M1 = S.randomMessage();
            int b = coinFlip();
            ModifiedPKEETFDA::Ciphertext challenge = S.encrypt(b ? M1 : M0, user.X.get(), user.Y.get());

            ModifiedPKEETFDA::Ciphertext forged = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());
            while (G.eq(forged.C1.get(), challenge.C1.get()))
                forged = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());
            forged.C2 = G.dup(challenge.C2.get());
            forged.C4 = challenge.C4;
            if (sameCiphertext(G, forged, challenge))
            {
                ++refusals;
                continue;
            }

            decRejected += !S.decrypt(forged, user.x.get(), user.y.get());
            auto td = S.auth(forged, user, testerList);
            autRejected += !td;
            correct += coinFlip() == b;
        }
        std::string tag = " (n=" + std::to_string(n) + ")";
        std::printf("  n=%zu: Aut returned bottom %d/%d, Dec returned bottom %d/%d, b guessed %d/%d (coin flip after bottom)\n",
                    n, autRejected, kAttackTrials, decRejected, kAttackTrials, correct, kAttackTrials);
        check(refusals == 0, "A on ModifiedPKEETFDA: forged ciphertext always differs from CT*" + tag);
        check(autRejected == kAttackTrials, "A on ModifiedPKEETFDA: Aut returns bottom for every forged ciphertext" + tag);
        check(decRejected == kAttackTrials, "A on ModifiedPKEETFDA: Dec returns bottom for every forged ciphertext" + tag);
    }
}

static void attackModifiedPKEETFDAB(const Group &G)
{
    std::printf("\n=== Attack B on ModifiedPKEETFDA: own ciphertext + forged ciphertext with (C2*, C4*), no tester key ===\n");
    ModifiedPKEETFDA S(G);

    for (size_t n : {1, 5})
    {
        int ownAccepted = 0, forgedRejected = 0, correct = 0;
        for (int t = 0; t < kAttackTrials; t++)
        {
            ModifiedPKEETFDA::UserKey user = S.userGen();
            std::vector<ModifiedPKEETFDA::TesterKey> honestTesters;
            for (size_t k = 0; k < n; k++)
                honestTesters.push_back(S.testerGen());
            auto honestKeys = publicKeysOf(honestTesters);

            ModifiedPKEETFDA::Message M0 = S.randomMessage(), M1 = S.randomMessage();
            int b = coinFlip();
            ModifiedPKEETFDA::Ciphertext challenge = S.encrypt(b ? M1 : M0, user.X.get(), user.Y.get());

            ModifiedPKEETFDA::Ciphertext own = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());
            ownAccepted += S.auth(own, user, honestKeys).has_value();

            ModifiedPKEETFDA::Ciphertext forged = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());
            forged.C2 = G.dup(challenge.C2.get());
            forged.C4 = challenge.C4;
            forgedRejected += !S.auth(forged, user, honestKeys);
            correct += coinFlip() == b;
        }
        std::string tag = " (n=" + std::to_string(n) + ")";
        std::printf("  n=%zu: own ciphertext accepted by Aut %d/%d, forged ciphertext Aut bottom %d/%d, b guessed %d/%d (coin flip)\n",
                    n, ownAccepted, kAttackTrials, forgedRejected, kAttackTrials, correct, kAttackTrials);
        check(ownAccepted == kAttackTrials, "B on ModifiedPKEETFDA: Aut accepts the adversary's honestly formed ciphertext" + tag);
        check(forgedRejected == kAttackTrials, "B on ModifiedPKEETFDA: Aut returns bottom for every forged ciphertext" + tag);
    }
}

static void attackModifiedPKEETFDAC(const Group &G)
{
    std::printf("\n=== Attack C on ModifiedPKEETFDA (Type-III): Aut on CT* and on an honest encryption of M0 ===\n");
    ModifiedPKEETFDA S(G);

    auto kFromConstantTerm = [&](const ModifiedPKEETFDA::Ciphertext &ct, const ModifiedPKEETFDA::Trapdoor &td) -> std::optional<Bn> {
        if (BN_is_zero(td.a[0].get()))
            return std::nullopt;
        return G.mulZp(ct.C3.get(), G.inv(td.a[0].get()).get());
    };

    for (size_t n : {1, 5})
    {
        int correct = 0, heuristicSaidEqual = 0;
        for (int t = 0; t < kAttackTrials; t++)
        {
            ModifiedPKEETFDA::UserKey user = S.userGen();
            std::vector<ModifiedPKEETFDA::TesterKey> honestTesters;
            for (size_t k = 0; k < n; k++)
                honestTesters.push_back(S.testerGen());
            auto honestKeys = publicKeysOf(honestTesters);

            ModifiedPKEETFDA::Message M0 = S.randomMessage(), M1 = S.randomMessage();
            int b = coinFlip();
            ModifiedPKEETFDA::Ciphertext challenge = S.encrypt(b ? M1 : M0, user.X.get(), user.Y.get());
            ModifiedPKEETFDA::Ciphertext ofM0 = S.encrypt(M0, user.X.get(), user.Y.get());

            auto challengeTd = S.auth(challenge, user, honestKeys);
            auto ofM0Td = S.auth(ofM0, user, honestKeys);

            int guess = coinFlip();
            auto kChallenge = kFromConstantTerm(challenge, *challengeTd);
            auto kOfM0 = kFromConstantTerm(ofM0, *ofM0Td);
            if (kChallenge && kOfM0)
            {
                Bn exponent = G.mulZp(kOfM0->get(), G.inv(kChallenge->get()).get());
                if (G.eq(G.exp(challenge.C1.get(), exponent.get()).get(), ofM0.C1.get()))
                {
                    ++heuristicSaidEqual;
                    guess = 0;
                }
            }
            correct += guess == b;
        }
        std::string tag = " (n=" + std::to_string(n) + ")";
        std::printf("  n=%zu: b guessed %d/%d (LGZ22-style eta = 0 / constant-term test fired %d times)\n",
                    n, correct, kAttackTrials, heuristicSaidEqual);
        check(correct >= 450 && correct <= 550, "C on ModifiedPKEETFDA: success rate stays near 1/2 (450..550 of 1000)" + tag);
    }
}

static void attackModifiedPKEETFDATransplantStrategies(const Group &G)
{
    std::printf("\n=== ModifiedPKEETFDA: same transplant strategies against the Aut/Dec oracles ===\n");
    ModifiedPKEETFDA S(G);

    const int trials = 100;
    const size_t n = 5;
    int accepted[4] = {0, 0, 0, 0};
    const char *strategy[4] = {
        "own (C2, C4) with challenge (C1*, C3*)",
        "challenge (C2*, C4*) with own (C1, C3)",
        "challenge ciphertext with C3* scaled by s",
        "challenge ciphertext with C4* xor delta",
    };

    for (int t = 0; t < trials; t++)
    {
        ModifiedPKEETFDA::UserKey user = S.userGen();
        std::vector<ModifiedPKEETFDA::TesterKey> testers;
        for (size_t k = 0; k < n; k++)
            testers.push_back(S.testerGen());
        auto keys = publicKeysOf(testers);

        ModifiedPKEETFDA::Ciphertext challenge = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());
        ModifiedPKEETFDA::Ciphertext own = S.encrypt(S.randomMessage(), user.X.get(), user.Y.get());

        ModifiedPKEETFDA::Ciphertext forged[4];
        forged[0] = copyOf(G, own);
        forged[0].C1 = G.dup(challenge.C1.get());
        forged[0].C3 = G.dup(challenge.C3.get());

        forged[1] = copyOf(G, own);
        forged[1].C2 = G.dup(challenge.C2.get());
        forged[1].C4 = challenge.C4;

        forged[2] = copyOf(G, challenge);
        forged[2].C3 = G.mulZp(challenge.C3.get(), G.randZpStar().get());

        forged[3] = copyOf(G, challenge);
        uint8_t delta[ModifiedPKEETFDA::kC4Bytes];
        RAND_bytes(delta, sizeof(delta));
        delta[0] |= 1;
        for (size_t i = 0; i < ModifiedPKEETFDA::kC4Bytes; i++)
            forged[3].C4[i] ^= delta[i];

        for (int s = 0; s < 4; s++)
            if (S.auth(forged[s], user, keys) || S.decrypt(forged[s], user.x.get(), user.y.get()))
                ++accepted[s];
    }

    for (int s = 0; s < 4; s++)
    {
        std::printf("  %-45s accepted by Aut or Dec: %d/%d\n", strategy[s], accepted[s], trials);
        check(accepted[s] == 0, std::string("Aut and Dec return bottom for ") + strategy[s]);
    }
}

int main()
{
    Group::requireLinkedOpenSSL3();
    std::printf("OpenSSL (linked): %s\n", Group::linkedOpenSSLVersion().c_str());

    Group G;
    testGroupEncoding(G);
    testLGZ22(G);
    attackLGZ22A(G);
    attackLGZ22B(G);
    attackLGZ22C(G);
    testModifiedPKEETFDA(G);
    attackModifiedPKEETFDAA(G);
    attackModifiedPKEETFDAB(G);
    attackModifiedPKEETFDAC(G);
    attackModifiedPKEETFDATransplantStrategies(G);

    std::printf("\n%d passed, %d failed\n", g_passes, g_failures);
    return g_failures == 0 ? 0 : 1;
}
