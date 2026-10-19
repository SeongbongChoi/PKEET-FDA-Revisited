#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <memory>
#include <ctime>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <sys/utsname.h>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include "Group.h"
#include "LGZ22.h"
#include "ModifiedPKEETFDA.h"

#ifndef PKEET_CXX_FLAGS
#define PKEET_CXX_FLAGS "unknown"
#endif

using namespace pkeet;

static std::string firstLineValue(const std::string &path, const std::string &key, char separator)
{
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line))
    {
        if (line.compare(0, key.size(), key) != 0)
            continue;
        size_t pos = line.find(separator);
        if (pos == std::string::npos)
            continue;
        std::string value = line.substr(pos + 1);
        size_t begin = value.find_first_not_of(" \t\"");
        size_t end = value.find_last_not_of(" \t\"");
        return begin == std::string::npos ? "" : value.substr(begin, end - begin + 1);
    }
    return "unknown";
}

static std::string wholeFile(const std::string &path)
{
    std::ifstream in(path);
    std::string line;
    if (!std::getline(in, line))
        return "unknown";
    return line;
}

static std::vector<std::pair<std::string, std::string>> describeEnvironment()
{
    utsname uts{};
    uname(&uts);

    char timestamp[64];
    std::time_t now = std::time(nullptr);
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", std::localtime(&now));

    return {
        {"timestamp", timestamp},
        {"cpu_model", firstLineValue("/proc/cpuinfo", "model name", ':')},
        {"cpu_governor", wholeFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")},
        {"os", firstLineValue("/etc/os-release", "PRETTY_NAME", '=')},
        {"kernel", std::string(uts.sysname) + " " + uts.release + " " + uts.machine},
        {"compiler", std::string("GCC ") + __VERSION__},
        {"cxx_flags", PKEET_CXX_FLAGS},
        {"openssl_linked", Group::linkedOpenSSLVersion()},
        {"openssl_headers", OPENSSL_VERSION_TEXT},
        {"openssl_cflags", OpenSSL_version(OPENSSL_CFLAGS)},
        {"openssl_platform", OpenSSL_version(OPENSSL_PLATFORM)},
        {"curve", "prime256v1 (P-256)"},
        {"point_encoding", "compressed, 33 bytes"},
        {"exponentiation", "EC_POINT_mul(group, r, NULL, P, a, ctx) for every base including g; no fixed-base precomputation"},
        {"hash", "SHAKE256 with 1-byte domain prefix"},
        {"threads", "1"},
    };
}

struct Options
{
    int warmup = 20;
    int reps = 100;
    double warmupSeconds = 1.0;
    std::vector<size_t> ns = {1, 2, 5, 10, 20, 50, 100};
    std::string csvPath = "pkeet_bench.csv";
};

using TimedCall = std::function<bool()>;
using Prepare = std::function<TimedCall()>;

struct Case
{
    Case(std::string scheme_, std::string algorithm_, std::string n_, uint64_t expectedTotal_,
         std::string formula_, Prepare prepare_)
        : scheme(std::move(scheme_)), algorithm(std::move(algorithm_)), n(std::move(n_)),
          expectedTotal(expectedTotal_), formula(std::move(formula_)), prepare(std::move(prepare_))
    {
    }

    std::string scheme, algorithm, n;
    uint64_t expectedTotal;
    std::string formula;
    Prepare prepare;
    std::vector<double> samples;
};

struct Row
{
    std::string scheme, algorithm, n;
    int warmup, reps;
    double meanMs, stddevMs, medianMs, minMs, maxMs;
    uint64_t exps;
    std::string formula;
};

static std::vector<Row> g_rows;

static std::string label(const Case &c)
{
    return c.scheme + " " + c.algorithm + (c.n.empty() ? "" : " n=" + c.n);
}

static void runOnce(Case &c, bool record)
{
    TimedCall call = c.prepare();

    uint64_t before = g_expCount;
    auto t0 = std::chrono::steady_clock::now();
    bool ok = call();
    auto t1 = std::chrono::steady_clock::now();
    uint64_t used = g_expCount - before;

    if (!ok)
        fatal(label(c) + ": wrong result");
    if (used != c.expectedTotal)
        fatal(label(c) + ": " + std::to_string(used) + " Exp, expected "
              + std::to_string(c.expectedTotal) + " (" + c.formula + ")");

    if (record)
        c.samples.push_back(std::chrono::duration<double, std::milli>(t1 - t0).count());
}

static void summarize(const Options &opt, const Case &c)
{
    const std::vector<double> &s = c.samples;
    double sum = 0;
    for (double v : s)
        sum += v;
    double mean = sum / s.size();
    double sq = 0;
    for (double v : s)
        sq += (v - mean) * (v - mean);
    double stddev = s.size() > 1 ? std::sqrt(sq / (s.size() - 1)) : 0.0;
    std::vector<double> sorted = s;
    std::sort(sorted.begin(), sorted.end());
    size_t mid = sorted.size() / 2;
    double median = sorted.size() % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;

    g_rows.push_back({c.scheme, c.algorithm, c.n, opt.warmup, opt.reps, mean, stddev, median,
                      sorted.front(), sorted.back(), c.expectedTotal, c.formula});
    std::printf("  %-16s %-22s n=%-4s median %9.4f ms  Exp %4llu (%s)\n",
                c.scheme.c_str(), c.algorithm.c_str(), c.n.empty() ? "-" : c.n.c_str(), median,
                (unsigned long long)c.expectedTotal, c.formula.c_str());
    std::fflush(stdout);
}

static void timeBasedWarmup(const Group &G, double seconds)
{
    Bn a = G.randZpStar();
    Pt P = G.expG(G.randZpStar().get());
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count() < seconds)
        for (int i = 0; i < 64; i++)
            P = G.exp(P.get(), a.get());
}

static void runInterleaved(const Options &opt, const Group &G, std::vector<Case> cases)
{
    timeBasedWarmup(G, opt.warmupSeconds);
    for (int rep = 0; rep < opt.warmup + opt.reps; rep++)
    {
        bool record = rep >= opt.warmup;
        if (rep % 2 == 0)
            for (size_t i = 0; i < cases.size(); i++)
                runOnce(cases[i], record);
        else
            for (size_t i = cases.size(); i-- > 0;)
                runOnce(cases[i], record);
    }
    for (const Case &c : cases)
        summarize(opt, c);
}

struct LGZ22State
{
    LGZ22::ServerKey server;
    LGZ22::UserKey user;
    std::vector<LGZ22::TesterKey> testers;
    std::vector<const EC_POINT *> testerKeys;
    Bn m, otherM;
    LGZ22::Ciphertext ctA, ctB;
    LGZ22::Trapdoor tdA, tdB;
    LGZ22::Ciphertext encOut;
    LGZ22::Trapdoor autOut;
    std::optional<Bn> decOut;
};

struct ModifiedPKEETFDAState
{
    ModifiedPKEETFDA::UserKey user;
    std::vector<ModifiedPKEETFDA::TesterKey> testers;
    std::vector<const EC_POINT *> testerKeys;
    ModifiedPKEETFDA::Message M, otherM;
    ModifiedPKEETFDA::Ciphertext ctA, ctB;
    std::optional<ModifiedPKEETFDA::Trapdoor> tdA, tdB;
    ModifiedPKEETFDA::Ciphertext encOut;
    std::optional<ModifiedPKEETFDA::Trapdoor> autOut;
    std::optional<ModifiedPKEETFDA::Message> decOut;
};

static std::shared_ptr<LGZ22State> freshLGZ22(const LGZ22 &S, size_t n)
{
    auto st = std::make_shared<LGZ22State>();
    st->server = S.serverGen();
    st->user = S.userGen();
    for (size_t k = 0; k < n; k++)
        st->testers.push_back(S.testerGen());
    st->testerKeys = publicKeysOf(st->testers);
    st->m = S.randomMessage();
    st->otherM = S.randomMessage();
    return st;
}

static std::shared_ptr<ModifiedPKEETFDAState> freshModifiedPKEETFDA(const ModifiedPKEETFDA &S, size_t n)
{
    auto st = std::make_shared<ModifiedPKEETFDAState>();
    st->user = S.userGen();
    for (size_t k = 0; k < n; k++)
        st->testers.push_back(S.testerGen());
    st->testerKeys = publicKeysOf(st->testers);
    st->M = S.randomMessage();
    st->otherM = S.randomMessage();
    return st;
}

static void benchPrimitives(const Options &opt, const Group &G)
{
    std::vector<Case> cases;
    cases.push_back({"P-256", "exp_base_g", "", 1, "g^a", [&G] {
        auto a = std::make_shared<Bn>(G.randZpStar());
        auto out = std::make_shared<Pt>();
        return TimedCall([&G, a, out] { *out = G.exp(G.generator(), a->get()); return true; });
    }});
    cases.push_back({"P-256", "exp_base_random_point", "", 1, "Q^a", [&G] {
        auto a = std::make_shared<Bn>(G.randZpStar());
        auto Q = std::make_shared<Pt>(G.expG(G.randZpStar().get()));
        auto out = std::make_shared<Pt>();
        return TimedCall([&G, a, Q, out] { *out = G.exp(Q->get(), a->get()); return true; });
    }});
    cases.push_back({"P-256", "hash_point_to_Zp", "", 0, "SHAKE256 384-bit mod p", [&G] {
        auto enc = std::make_shared<PointBytes>(G.encodeCompressedOrZeroForIdentity(G.expG(G.randZpStar().get()).get()));
        auto out = std::make_shared<Bn>();
        return TimedCall([&G, enc, out] { *out = G.hashToZp(0x02, {*enc}); return true; });
    }});
    runInterleaved(opt, G, std::move(cases));

    const Row &baseG = g_rows[g_rows.size() - 3];
    const Row &baseRandom = g_rows[g_rows.size() - 2];
    std::printf("  median g^a / median Q^a = %.4f / %.4f ms = %.3f\n",
                baseG.medianMs, baseRandom.medianMs, baseG.medianMs / baseRandom.medianMs);
}

static void benchEncDec(const Options &opt, const Group &G, const LGZ22 &L, const ModifiedPKEETFDA &M)
{
    std::vector<Case> enc;
    enc.push_back({"LGZ22", "Enc", "", 6, "6", [&] {
        auto st = freshLGZ22(L, 0);
        return TimedCall([&L, st] {
            st->encOut = L.encrypt(st->m.get(), st->user.X.get(), st->user.Y.get(), st->server.Xc.get());
            return true;
        });
    }});
    enc.push_back({"ModifiedPKEETFDA", "Enc", "", 4, "4", [&] {
        auto st = freshModifiedPKEETFDA(M, 0);
        return TimedCall([&M, st] {
            st->encOut = M.encrypt(st->M, st->user.X.get(), st->user.Y.get());
            return true;
        });
    }});
    runInterleaved(opt, G, std::move(enc));

    std::vector<Case> dec;
    dec.push_back({"LGZ22", "Dec", "", 2, "2", [&] {
        auto st = freshLGZ22(L, 0);
        st->ctA = L.encrypt(st->m.get(), st->user.X.get(), st->user.Y.get(), st->server.Xc.get());
        return TimedCall([&L, st] {
            st->decOut = L.decrypt(st->ctA, st->user.x.get());
            return st->decOut && BN_cmp(st->decOut->get(), st->m.get()) == 0;
        });
    }});
    dec.push_back({"ModifiedPKEETFDA", "Dec", "", 4, "4", [&] {
        auto st = freshModifiedPKEETFDA(M, 0);
        st->ctA = M.encrypt(st->M, st->user.X.get(), st->user.Y.get());
        return TimedCall([&M, st] {
            st->decOut = M.decrypt(st->ctA, st->user.x.get(), st->user.y.get());
            return st->decOut && *st->decOut == st->M;
        });
    }});
    runInterleaved(opt, G, std::move(dec));
}

static void benchAut(const Options &opt, const Group &G, const LGZ22 &L, const ModifiedPKEETFDA &M, size_t n)
{
    std::string ns = std::to_string(n);
    std::vector<Case> cases;
    cases.push_back({"LGZ22", "Aut", ns, 2 * n + 2, "2n+2", [&, n] {
        auto st = freshLGZ22(L, n);
        st->ctA = L.encrypt(st->m.get(), st->user.X.get(), st->user.Y.get(), st->server.Xc.get());
        return TimedCall([&L, st, n] {
            st->autOut = L.auth(st->ctA, st->user.y.get(), st->server.xc.get(), st->testerKeys);
            return st->autOut.td1.size() == n + 1;
        });
    }});
    auto modifiedAut = [&, n](ModifiedPKEETFDA::AuthMode mode) {
        return [&, n, mode] {
            auto st = freshModifiedPKEETFDA(M, n);
            st->ctA = M.encrypt(st->M, st->user.X.get(), st->user.Y.get());
            return TimedCall([&M, st, n, mode] {
                st->autOut = M.auth(st->ctA, st->user, st->testerKeys, mode);
                return st->autOut && st->autOut->a.size() == n;
            });
        };
    };
    cases.push_back({"ModifiedPKEETFDA", "Aut", ns, n + 5, "n+5", modifiedAut(ModifiedPKEETFDA::AuthMode::VerifyCiphertext)});
    cases.push_back({"ModifiedPKEETFDA", "Aut_skipverify", ns, n + 2, "n+2", modifiedAut(ModifiedPKEETFDA::AuthMode::SkipVerification)});
    runInterleaved(opt, G, std::move(cases));
}

static void benchAutBreakdown(const Options &opt, const Group &G, const ModifiedPKEETFDA &M, size_t n)
{
    std::string ns = std::to_string(n);
    std::vector<Case> cases;
    cases.push_back({"LGZ22", "Aut_part_expand_roots", ns, 0, "0", [&G, n] {
        auto roots = std::make_shared<std::vector<Bn>>();
        for (size_t k = 0; k < n; k++)
            roots->push_back(G.randZpStar());
        auto out = std::make_shared<std::vector<Bn>>();
        return TimedCall([&G, roots, out, n] {
            *out = G.expandRootsProduct(*roots);
            return out->size() == n + 1;
        });
    }});
    cases.push_back({"ModifiedPKEETFDA", "Aut_part_lagrange", ns, 0, "0", [&G, n] {
        auto xs = std::make_shared<std::vector<Bn>>();
        auto ys = std::make_shared<std::vector<Bn>>();
        for (size_t k = 0; k < n; k++)
        {
            xs->push_back(G.randZpStar());
            ys->push_back(G.randZpStar());
        }
        auto out = std::make_shared<std::vector<Bn>>();
        return TimedCall([&G, xs, ys, out, n] {
            *out = G.interpolateCoefficients(*xs, *ys);
            return out->size() == n;
        });
    }});
    cases.push_back({"ModifiedPKEETFDA", "Aut_part_H4_x_n", ns, 0, "0", [&M, &G, n] {
        auto D = std::make_shared<Pt>(G.expG(G.randZpStar().get()));
        auto testerKeys = std::make_shared<std::vector<Pt>>();
        auto sharedPoints = std::make_shared<std::vector<Pt>>();
        for (size_t k = 0; k < n; k++)
        {
            testerKeys->push_back(G.expG(G.randZpStar().get()));
            sharedPoints->push_back(G.expG(G.randZpStar().get()));
        }
        auto out = std::make_shared<std::vector<ModifiedPKEETFDA::RhoSigma>>();
        out->reserve(n);
        return TimedCall([&M, D, testerKeys, sharedPoints, out, n] {
            for (size_t k = 0; k < n; k++)
                out->push_back(M.H4((*testerKeys)[k].get(), D->get(), (*sharedPoints)[k].get()));
            return out->size() == n;
        });
    }});
    runInterleaved(opt, G, std::move(cases));
}

static void benchTest(const Options &opt, const Group &G, const LGZ22 &L, const ModifiedPKEETFDA &M,
                      size_t n, bool sameMessage)
{
    std::string ns = std::to_string(n);
    std::string algorithm = sameMessage ? "Test_same" : "Test_diff";
    std::vector<Case> cases;
    cases.push_back({"LGZ22", algorithm, ns, 2 * n + 3, "2n+3", [&, n, sameMessage] {
        auto st = freshLGZ22(L, n);
        const BIGNUM *mB = sameMessage ? st->m.get() : st->otherM.get();
        st->ctA = L.encrypt(st->m.get(), st->user.X.get(), st->user.Y.get(), st->server.Xc.get());
        st->ctB = L.encrypt(mB, st->user.X.get(), st->user.Y.get(), st->server.Xc.get());
        st->tdA = L.auth(st->ctA, st->user.y.get(), st->server.xc.get(), st->testerKeys);
        st->tdB = L.auth(st->ctB, st->user.y.get(), st->server.xc.get(), st->testerKeys);
        return TimedCall([&L, st, sameMessage] {
            bool equal = L.test(st->ctA, st->tdA, st->ctB, st->tdB, st->testers[0].xt.get(), st->server.Xc.get());
            return equal == sameMessage;
        });
    }});
    cases.push_back({"ModifiedPKEETFDA", algorithm, ns, 3, "3", [&, n, sameMessage] {
        auto st = freshModifiedPKEETFDA(M, n);
        st->ctA = M.encrypt(st->M, st->user.X.get(), st->user.Y.get());
        st->ctB = M.encrypt(sameMessage ? st->M : st->otherM, st->user.X.get(), st->user.Y.get());
        st->tdA = M.auth(st->ctA, st->user, st->testerKeys);
        st->tdB = M.auth(st->ctB, st->user, st->testerKeys);
        if (!st->tdA || !st->tdB)
            fatal("ModifiedPKEETFDA Aut failed while preparing Test inputs");
        return TimedCall([&M, st, sameMessage] {
            bool equal = M.test(st->ctA, *st->tdA, st->ctB, *st->tdB, st->testers[0]);
            return equal == sameMessage;
        });
    }});
    runInterleaved(opt, G, std::move(cases));
}

static std::string csvEscape(const std::string &s)
{
    if (s.find_first_of(",\"\n") == std::string::npos)
        return s;
    std::string out = "\"";
    for (char c : s)
        out += c == '"' ? std::string("\"\"") : std::string(1, c);
    return out + "\"";
}

static void writeCsv(const Options &opt)
{
    std::ofstream out(opt.csvPath);
    if (!out)
        fatal("cannot open " + opt.csvPath);
    for (const auto &kv : describeEnvironment())
        out << "# " << kv.first << ": " << kv.second << "\n";
    out << "# warmup: " << opt.warmup << " runs per measurement, plus " << opt.warmupSeconds
        << " s time-based Exp warm-up at start and before each block\n";
    out << "# reps: " << opt.reps << "\n";
    out << "# inputs: fresh keys, messages, ciphertexts and tester keys per repetition; timed region = algorithm call only\n";
    out << "# interleaving: for each n, LGZ22 and ModifiedPKEETFDA alternate every repetition (order reversed on odd repetitions)\n";
    out << "scheme,algorithm,n,warmup,reps,mean_ms,stddev_ms,median_ms,min_ms,max_ms,exp_count,exp_formula\n";
    char buf[512];
    for (const Row &r : g_rows)
    {
        std::snprintf(buf, sizeof(buf), "%s,%s,%s,%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%llu,%s\n",
                      r.scheme.c_str(), r.algorithm.c_str(), r.n.c_str(), r.warmup, r.reps,
                      r.meanMs, r.stddevMs, r.medianMs, r.minMs, r.maxMs,
                      (unsigned long long)r.exps, csvEscape(r.formula).c_str());
        out << buf;
    }
}

static std::vector<size_t> parseList(const std::string &s)
{
    std::vector<size_t> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        long v = std::strtol(item.c_str(), nullptr, 10);
        if (v < 1)
            fatal("tester counts must be >= 1: " + s);
        out.push_back((size_t)v);
    }
    return out;
}

static void usage(const char *prog)
{
    std::fprintf(stderr,
                 "Usage: %s [-w warmup] [-W seconds] [-r reps] [-n 1,2,5,...] [-o out.csv]\n"
                 "  -w  warm-up runs per measurement (default 20)\n"
                 "  -W  time-based Exp warm-up before each block, >= 1 s (default 1.0)\n"
                 "  -r  timed runs per measurement   (default 100)\n"
                 "  -n  tester counts                (default 1,2,5,10,20,50,100)\n"
                 "  -o  CSV output path              (default pkeet_bench.csv)\n",
                 prog);
    std::exit(1);
}

int main(int argc, char **argv)
{
    Group::requireLinkedOpenSSL3();
    std::printf("OpenSSL (linked): %s\n", Group::linkedOpenSSLVersion().c_str());

    Options opt;
    for (int i = 1; i < argc; i++)
    {
        std::string a = argv[i];
        if (i + 1 >= argc) usage(argv[0]);
        if      (a == "-w") opt.warmup = std::atoi(argv[++i]);
        else if (a == "-W") opt.warmupSeconds = std::atof(argv[++i]);
        else if (a == "-r") opt.reps = std::atoi(argv[++i]);
        else if (a == "-n") opt.ns = parseList(argv[++i]);
        else if (a == "-o") opt.csvPath = argv[++i];
        else usage(argv[0]);
    }
    if (opt.reps < 1 || opt.warmup < 0 || opt.warmupSeconds < 1.0 || opt.ns.empty())
        usage(argv[0]);

    for (const auto &kv : describeEnvironment())
        std::printf("  %-16s %s\n", kv.first.c_str(), kv.second.c_str());
    std::printf("  warmup=%d reps=%d time_warmup=%.1fs per block\n\n", opt.warmup, opt.reps, opt.warmupSeconds);

    Group G;
    LGZ22 L(G);
    ModifiedPKEETFDA M(G);

    timeBasedWarmup(G, opt.warmupSeconds);
    benchPrimitives(opt, G);
    benchEncDec(opt, G, L, M);
    for (size_t n : opt.ns)
    {
        benchAut(opt, G, L, M, n);
        benchAutBreakdown(opt, G, M, n);
        benchTest(opt, G, L, M, n, true);
        benchTest(opt, G, L, M, n, false);
    }
    writeCsv(opt);
    std::printf("\nwrote %s\n", opt.csvPath.c_str());
    return 0;
}
