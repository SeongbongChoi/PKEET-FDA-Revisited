#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT/out"
SRC_DIR="$OUT/src"
DEPS_DIR="$OUT/deps"
PREFIX="$OUT/install"
LOG_DIR="$OUT/log"
STAMP_DIR="$PREFIX/.stamps"

OPENSSL_REPO="https://github.com/openssl/openssl.git"
OPENSSL_TAG="openssl-3.5.9"
OPENSSL_COMMIT="45e844fa2a14ec92d146bd8f5778ac130b6625fb"

OPENSSL_FLAGS=(
    no-shared no-tests no-docs no-apps
    enable-ec_nistp_64_gcc_128
    --libdir=lib
)

JOBS="$(nproc)"
FORCE=0
VERBOSE=0
TARGETS=()

usage() {
    cat <<'USAGE'
Builds PKEET-FDA-Revisited's dependency (OpenSSL) from pinned sources into
out/install.

Usage: ./build.sh [options] [target...]
  targets : deps (default: openssl + verify) | openssl | verify | clean
  -j N    : parallel jobs (default: nproc)
  -f      : force rebuild even if the install stamp is up to date
  -v      : stream build output instead of writing it to out/log/
USAGE
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -j)        JOBS="$2"; shift 2 ;;
        -j*)       JOBS="${1#-j}"; shift ;;
        -f)        FORCE=1; shift ;;
        -v)        VERBOSE=1; shift ;;
        -h|--help) usage ;;
        -*)        echo "unknown option: $1" >&2; usage 1 ;;
        *)         TARGETS+=("$1"); shift ;;
    esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=(deps)

info() { printf '\033[1;34m[%s]\033[0m %s\n' "$1" "$2"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

run() {
    local name="$1"; shift
    if [[ $VERBOSE -eq 1 ]]; then
        "$@"
        return
    fi
    local log="$LOG_DIR/$name.log"
    if ! "$@" >>"$log" 2>&1; then
        tail -n 30 "$log" >&2
        die "$name failed (full log: $log)"
    fi
}

fetch() {
    local name="$1" repo="$2" ref="$3" commit="$4"
    local dir="$SRC_DIR/$name"
    if [[ -d "$dir/.git" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$commit" ]]; then
        return
    fi
    info "$name" "fetching ${ref} (${commit:0:12})"
    rm -rf "$dir"
    mkdir -p "$dir"
    run "$name" git -C "$dir" init -q
    run "$name" git -C "$dir" fetch -q --depth 1 "$repo" "$ref"
    run "$name" git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
    local got
    got="$(git -C "$dir" rev-parse HEAD)"
    [[ "$got" == "$commit" ]] || die "$name: expected $commit, got $got"
}

stamp_of() { printf '%s\n' "$@" | sha256sum | cut -d' ' -f1; }

up_to_date() {
    local name="$1" stamp="$2"
    [[ $FORCE -eq 0 && -f "$STAMP_DIR/$name" && "$(cat "$STAMP_DIR/$name")" == "$stamp" ]]
}

build_openssl() {
    local stamp
    stamp="$(stamp_of "$OPENSSL_COMMIT" "${OPENSSL_FLAGS[@]}")"
    if up_to_date openssl "$stamp"; then
        info openssl "up to date ($OPENSSL_TAG)"
        return
    fi
    : >"$LOG_DIR/openssl.log"
    fetch openssl "$OPENSSL_REPO" "refs/tags/$OPENSSL_TAG" "$OPENSSL_COMMIT"

    local bdir="$DEPS_DIR/openssl"
    rm -rf "$bdir" "$PREFIX/include/openssl" "$PREFIX"/lib/lib{crypto,ssl}.* "$PREFIX/lib/pkgconfig"/{libcrypto,libssl,openssl}.pc
    mkdir -p "$bdir"
    info openssl "configuring ($OPENSSL_TAG)"
    (cd "$bdir" && run openssl "$SRC_DIR/openssl/Configure" \
        --prefix="$PREFIX" --openssldir="$PREFIX/ssl" "${OPENSSL_FLAGS[@]}")
    info openssl "building (-j$JOBS)"
    run openssl make -C "$bdir" -j "$JOBS"
    run openssl make -C "$bdir" install_sw

    [[ -f "$PREFIX/lib/libcrypto.a" && -f "$PREFIX/include/openssl/evp.h" ]] \
        || die "openssl: install incomplete"
    echo "$stamp" >"$STAMP_DIR/openssl"
    info openssl "installed -> $PREFIX"
}

verify() {
    local src="$DEPS_DIR/smoke_test.c" exe="$DEPS_DIR/smoke_test"
    info verify "building smoke test"
    : >"$LOG_DIR/verify.log"
    cat >"$src" <<'EOF'
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>

#define CHECK(cond, what)                                   \
    do {                                                    \
        if (!(cond)) {                                      \
            fprintf(stderr, "FAIL: %s\n", what);            \
            return 1;                                       \
        }                                                   \
        printf("  ok  %s\n", what);                         \
    } while (0)

static int test_shake256(void) {
    static const unsigned char expect[32] = {
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f,
        0xeb, 0x74, 0x3e, 0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8,
        0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f};
    unsigned char out[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx != NULL
          && EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) == 1
          && EVP_DigestFinalXOF(ctx, out, sizeof(out)) == 1;
    EVP_MD_CTX_free(ctx);
    CHECK(ok && memcmp(out, expect, 32) == 0, "SHAKE256 test vector (empty input)");
    return 0;
}

static int test_p256(void) {
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bn = BN_CTX_new();
    BIGNUM *a = BN_new(), *b = BN_new(), *ab = BN_new();
    EC_POINT *bG = EC_POINT_new(grp), *abG1 = EC_POINT_new(grp), *abG2 = EC_POINT_new(grp);
    EC_POINT *dec = EC_POINT_new(grp);
    unsigned char buf[65];
    const BIGNUM *n = EC_GROUP_get0_order(grp);

    int ok = BN_rand_range(a, n) && BN_rand_range(b, n)
          && BN_mod_mul(ab, a, b, n, bn)
          && EC_POINT_mul(grp, bG, b, NULL, NULL, bn)
          && EC_POINT_mul(grp, abG1, NULL, bG, a, bn)
          && EC_POINT_mul(grp, abG2, ab, NULL, NULL, bn);
    CHECK(ok && EC_POINT_cmp(grp, abG1, abG2, bn) == 0, "P-256 [a]([b]G) == [ab]G");

    size_t len = EC_POINT_point2oct(grp, abG1, POINT_CONVERSION_COMPRESSED, buf, sizeof(buf), bn);
    ok = len == 33 && EC_POINT_oct2point(grp, dec, buf, len, bn) == 1;
    CHECK(ok && EC_POINT_cmp(grp, abG1, dec, bn) == 0, "P-256 compressed serialize round-trip");
    printf("        |G| = %zu bytes (compressed), |p| = %d bits\n", len, BN_num_bits(n));

    EC_POINT_free(bG); EC_POINT_free(abG1); EC_POINT_free(abG2); EC_POINT_free(dec);
    BN_free(a); BN_free(b); BN_free(ab);
    BN_CTX_free(bn);
    EC_GROUP_free(grp);
    return 0;
}

int main(void) {
    printf("%s\n", OPENSSL_VERSION_TEXT);
    if (test_shake256()) return 1;
    return test_p256();
}
EOF
    run verify cc -O2 -I"$PREFIX/include" "$src" \
        "$PREFIX/lib/libcrypto.a" -lpthread -ldl -o "$exe"
    "$exe" || die "smoke test failed (source kept at $src)"
    rm -f "$src" "$exe"
}

for t in "${TARGETS[@]}"; do
    case "$t" in
        clean) info clean "removing $OUT"; rm -rf "$OUT"; continue ;;
        deps|openssl|verify) ;;
        *) die "unknown target: $t" ;;
    esac
    mkdir -p "$SRC_DIR" "$DEPS_DIR" "$PREFIX" "$LOG_DIR" "$STAMP_DIR"
    case "$t" in
        deps)    build_openssl; verify ;;
        openssl) build_openssl ;;
        verify)  verify ;;
    esac
done
