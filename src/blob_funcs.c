/*
Copyright 2018 Shawn Wagner

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3ext.h>
#include <string.h>

#if defined(__GNUC__) && (defined(__x86_64) || defined(__i386))
#include <nmmintrin.h>
#endif

#include "config.h"

#ifdef ZLIB_FOUND
#include <arpa/inet.h>
#include <zlib.h>
#endif

SQLITE_EXTENSION_INIT1

static char *to_hex(const unsigned char *bytes, int len) {
  static const char hexdigits[] = "0123456789ABCDEF";
  char *output = sqlite3_malloc(len * 2 + 1);
  if (!output) {
    return NULL;
  }
  int i = 0;
  for (int n = 0; n < len; n += 1) {
    output[i++] = hexdigits[bytes[n] >> 4];
    output[i++] = hexdigits[bytes[n] & 0xF];
  }
  output[i] = '\0';
  return output;
}

static void bf_md5(sqlite3_context *ctx, int nargs __attribute__((unused)),
                   sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }

  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);
  unsigned char md[MD5_DIGEST_LENGTH];
  if (!MD5(data, datalen, md)) {
    sqlite3_result_error(ctx, "MD5 failed", -1);
    return;
  }
  char *hex = to_hex(md, MD5_DIGEST_LENGTH);
  if (!hex) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  sqlite3_result_text(ctx, hex, MD5_DIGEST_LENGTH * 2, sqlite3_free);
}

static void bf_sha1(sqlite3_context *ctx, int nargs __attribute__((unused)),
                    sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }

  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);
  unsigned char md[SHA_DIGEST_LENGTH];
  if (!SHA1(data, datalen, md)) {
    sqlite3_result_error(ctx, "SHA1 failed", -1);
    return;
  }
  char *hex = to_hex(md, SHA_DIGEST_LENGTH);
  if (!hex) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  sqlite3_result_text(ctx, hex, SHA_DIGEST_LENGTH * 2, sqlite3_free);
}

static const EVP_MD *get_sha2_algo(int bits) {
  switch (bits) {
  case 224:
    return EVP_sha224();
  case 0:
  case 256:
    return EVP_sha256();
  case 384:
    return EVP_sha384();
  case 512:
    return EVP_sha512();
  default:
    return NULL;
  }
}

static void bf_sha2(sqlite3_context *ctx, int nargs, sqlite3_value **args) {

  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  if (nargs == 2 && sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }
  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);

  int bits = 0;
  if (nargs == 2) {
    bits = sqlite3_value_int(args[1]);
  }

  const EVP_MD *algo = get_sha2_algo(bits);
  if (!algo) {
    return;
  }

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen;
  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  if (!hashctx) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!EVP_DigestInit_ex(hashctx, algo, NULL)) {
    sqlite3_result_error(ctx, "EVP_DigestInit_ex failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  if (!EVP_DigestUpdate(hashctx, data, datalen)) {
    sqlite3_result_error(ctx, "EVP_DigestUpdate failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  if (!EVP_DigestFinal_ex(hashctx, md, &mdlen)) {
    sqlite3_result_error(ctx, "EVP_DigestFinal_ex failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  EVP_MD_CTX_free(hashctx);
  char *hex = to_hex(md, mdlen);
  if (!hex) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  sqlite3_result_text(ctx, hex, mdlen * 2, sqlite3_free);
}

// Start of code taken from sqlite3 shathree.c

/*
** 2017-03-08
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
******************************************************************************
**
** This SQLite extension implements a functions that compute SHA1 hashes.
** Two SQL functions are implemented:
**
**     sha3(X,SIZE)
**     sha3_query(Y,SIZE)
**
** The sha3(X) function computes the SHA3 hash of the input X, or NULL if
** X is NULL.
**
** The sha3_query(Y) function evalutes all queries in the SQL statements of Y
** and returns a hash of their results.
**
** The SIZE argument is optional.  If omitted, the SHA3-256 hash algorithm
** is used.  If SIZE is included it must be one of the integers 224, 256,
** 384, or 512, to determine SHA3 hash variant that is computed.
*/
#include <assert.h>
#include <stdarg.h>
#include <string.h>
typedef sqlite3_uint64 u64;

/******************************************************************************
** The Hash Engine
*/
/*
** Macros to determine whether the machine is big or little endian,
** and whether or not that determination is run-time or compile-time.
**
** For best performance, an attempt is made to guess at the byte-order
** using C-preprocessor macros.  If that is unsuccessful, or if
** -DSHA3_BYTEORDER=0 is set, then byte-order is determined
** at run-time.
*/
#ifndef SHA3_BYTEORDER
#if defined(i386) || defined(__i386__) || defined(_M_IX86) ||                  \
    defined(__x86_64) || defined(__x86_64__) || defined(_M_X64) ||             \
    defined(_M_AMD64) || defined(_M_ARM) || defined(__x86) || defined(__arm__)
#define SHA3_BYTEORDER 1234
#elif defined(sparc) || defined(__ppc__)
#define SHA3_BYTEORDER 4321
#else
#define SHA3_BYTEORDER 0
#endif
#endif

/*
** State structure for a SHA3 hash in progress
*/
typedef struct SHA3Context SHA3Context;
struct SHA3Context {
  union {
    u64 s[25];             /* Keccak state. 5x5 lines of 64 bits each */
    unsigned char x[1600]; /* ... or 1600 bytes */
  } u;
  unsigned nRate;   /* Bytes of input accepted per Keccak iteration */
  unsigned nLoaded; /* Input bytes loaded into u.x[] so far this cycle */
  unsigned ixMask;  /* Insert next input into u.x[nLoaded^ixMask]. */
};

/*
** A single step of the Keccak mixing function for a 1600-bit state
*/
static void KeccakF1600Step(SHA3Context *p) {
  int i;
  u64 b0, b1, b2, b3, b4;
  u64 c0, c1, c2, c3, c4;
  u64 d0, d1, d2, d3, d4;
  static const u64 RC[] = {
      0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
      0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
      0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
      0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
      0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
      0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
      0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
      0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
#define a00 (p->u.s[0])
#define a01 (p->u.s[1])
#define a02 (p->u.s[2])
#define a03 (p->u.s[3])
#define a04 (p->u.s[4])
#define a10 (p->u.s[5])
#define a11 (p->u.s[6])
#define a12 (p->u.s[7])
#define a13 (p->u.s[8])
#define a14 (p->u.s[9])
#define a20 (p->u.s[10])
#define a21 (p->u.s[11])
#define a22 (p->u.s[12])
#define a23 (p->u.s[13])
#define a24 (p->u.s[14])
#define a30 (p->u.s[15])
#define a31 (p->u.s[16])
#define a32 (p->u.s[17])
#define a33 (p->u.s[18])
#define a34 (p->u.s[19])
#define a40 (p->u.s[20])
#define a41 (p->u.s[21])
#define a42 (p->u.s[22])
#define a43 (p->u.s[23])
#define a44 (p->u.s[24])
#define ROL64(a, x) ((a << x) | (a >> (64 - x)))

  for (i = 0; i < 24; i += 4) {
    c0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
    c1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
    c2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
    c3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
    c4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;
    d0 = c4 ^ ROL64(c1, 1);
    d1 = c0 ^ ROL64(c2, 1);
    d2 = c1 ^ ROL64(c3, 1);
    d3 = c2 ^ ROL64(c4, 1);
    d4 = c3 ^ ROL64(c0, 1);

    b0 = (a00 ^ d0);
    b1 = ROL64((a11 ^ d1), 44);
    b2 = ROL64((a22 ^ d2), 43);
    b3 = ROL64((a33 ^ d3), 21);
    b4 = ROL64((a44 ^ d4), 14);
    a00 = b0 ^ ((~b1) & b2);
    a00 ^= RC[i];
    a11 = b1 ^ ((~b2) & b3);
    a22 = b2 ^ ((~b3) & b4);
    a33 = b3 ^ ((~b4) & b0);
    a44 = b4 ^ ((~b0) & b1);

    b2 = ROL64((a20 ^ d0), 3);
    b3 = ROL64((a31 ^ d1), 45);
    b4 = ROL64((a42 ^ d2), 61);
    b0 = ROL64((a03 ^ d3), 28);
    b1 = ROL64((a14 ^ d4), 20);
    a20 = b0 ^ ((~b1) & b2);
    a31 = b1 ^ ((~b2) & b3);
    a42 = b2 ^ ((~b3) & b4);
    a03 = b3 ^ ((~b4) & b0);
    a14 = b4 ^ ((~b0) & b1);

    b4 = ROL64((a40 ^ d0), 18);
    b0 = ROL64((a01 ^ d1), 1);
    b1 = ROL64((a12 ^ d2), 6);
    b2 = ROL64((a23 ^ d3), 25);
    b3 = ROL64((a34 ^ d4), 8);
    a40 = b0 ^ ((~b1) & b2);
    a01 = b1 ^ ((~b2) & b3);
    a12 = b2 ^ ((~b3) & b4);
    a23 = b3 ^ ((~b4) & b0);
    a34 = b4 ^ ((~b0) & b1);

    b1 = ROL64((a10 ^ d0), 36);
    b2 = ROL64((a21 ^ d1), 10);
    b3 = ROL64((a32 ^ d2), 15);
    b4 = ROL64((a43 ^ d3), 56);
    b0 = ROL64((a04 ^ d4), 27);
    a10 = b0 ^ ((~b1) & b2);
    a21 = b1 ^ ((~b2) & b3);
    a32 = b2 ^ ((~b3) & b4);
    a43 = b3 ^ ((~b4) & b0);
    a04 = b4 ^ ((~b0) & b1);

    b3 = ROL64((a30 ^ d0), 41);
    b4 = ROL64((a41 ^ d1), 2);
    b0 = ROL64((a02 ^ d2), 62);
    b1 = ROL64((a13 ^ d3), 55);
    b2 = ROL64((a24 ^ d4), 39);
    a30 = b0 ^ ((~b1) & b2);
    a41 = b1 ^ ((~b2) & b3);
    a02 = b2 ^ ((~b3) & b4);
    a13 = b3 ^ ((~b4) & b0);
    a24 = b4 ^ ((~b0) & b1);

    c0 = a00 ^ a20 ^ a40 ^ a10 ^ a30;
    c1 = a11 ^ a31 ^ a01 ^ a21 ^ a41;
    c2 = a22 ^ a42 ^ a12 ^ a32 ^ a02;
    c3 = a33 ^ a03 ^ a23 ^ a43 ^ a13;
    c4 = a44 ^ a14 ^ a34 ^ a04 ^ a24;
    d0 = c4 ^ ROL64(c1, 1);
    d1 = c0 ^ ROL64(c2, 1);
    d2 = c1 ^ ROL64(c3, 1);
    d3 = c2 ^ ROL64(c4, 1);
    d4 = c3 ^ ROL64(c0, 1);

    b0 = (a00 ^ d0);
    b1 = ROL64((a31 ^ d1), 44);
    b2 = ROL64((a12 ^ d2), 43);
    b3 = ROL64((a43 ^ d3), 21);
    b4 = ROL64((a24 ^ d4), 14);
    a00 = b0 ^ ((~b1) & b2);
    a00 ^= RC[i + 1];
    a31 = b1 ^ ((~b2) & b3);
    a12 = b2 ^ ((~b3) & b4);
    a43 = b3 ^ ((~b4) & b0);
    a24 = b4 ^ ((~b0) & b1);

    b2 = ROL64((a40 ^ d0), 3);
    b3 = ROL64((a21 ^ d1), 45);
    b4 = ROL64((a02 ^ d2), 61);
    b0 = ROL64((a33 ^ d3), 28);
    b1 = ROL64((a14 ^ d4), 20);
    a40 = b0 ^ ((~b1) & b2);
    a21 = b1 ^ ((~b2) & b3);
    a02 = b2 ^ ((~b3) & b4);
    a33 = b3 ^ ((~b4) & b0);
    a14 = b4 ^ ((~b0) & b1);

    b4 = ROL64((a30 ^ d0), 18);
    b0 = ROL64((a11 ^ d1), 1);
    b1 = ROL64((a42 ^ d2), 6);
    b2 = ROL64((a23 ^ d3), 25);
    b3 = ROL64((a04 ^ d4), 8);
    a30 = b0 ^ ((~b1) & b2);
    a11 = b1 ^ ((~b2) & b3);
    a42 = b2 ^ ((~b3) & b4);
    a23 = b3 ^ ((~b4) & b0);
    a04 = b4 ^ ((~b0) & b1);

    b1 = ROL64((a20 ^ d0), 36);
    b2 = ROL64((a01 ^ d1), 10);
    b3 = ROL64((a32 ^ d2), 15);
    b4 = ROL64((a13 ^ d3), 56);
    b0 = ROL64((a44 ^ d4), 27);
    a20 = b0 ^ ((~b1) & b2);
    a01 = b1 ^ ((~b2) & b3);
    a32 = b2 ^ ((~b3) & b4);
    a13 = b3 ^ ((~b4) & b0);
    a44 = b4 ^ ((~b0) & b1);

    b3 = ROL64((a10 ^ d0), 41);
    b4 = ROL64((a41 ^ d1), 2);
    b0 = ROL64((a22 ^ d2), 62);
    b1 = ROL64((a03 ^ d3), 55);
    b2 = ROL64((a34 ^ d4), 39);
    a10 = b0 ^ ((~b1) & b2);
    a41 = b1 ^ ((~b2) & b3);
    a22 = b2 ^ ((~b3) & b4);
    a03 = b3 ^ ((~b4) & b0);
    a34 = b4 ^ ((~b0) & b1);

    c0 = a00 ^ a40 ^ a30 ^ a20 ^ a10;
    c1 = a31 ^ a21 ^ a11 ^ a01 ^ a41;
    c2 = a12 ^ a02 ^ a42 ^ a32 ^ a22;
    c3 = a43 ^ a33 ^ a23 ^ a13 ^ a03;
    c4 = a24 ^ a14 ^ a04 ^ a44 ^ a34;
    d0 = c4 ^ ROL64(c1, 1);
    d1 = c0 ^ ROL64(c2, 1);
    d2 = c1 ^ ROL64(c3, 1);
    d3 = c2 ^ ROL64(c4, 1);
    d4 = c3 ^ ROL64(c0, 1);

    b0 = (a00 ^ d0);
    b1 = ROL64((a21 ^ d1), 44);
    b2 = ROL64((a42 ^ d2), 43);
    b3 = ROL64((a13 ^ d3), 21);
    b4 = ROL64((a34 ^ d4), 14);
    a00 = b0 ^ ((~b1) & b2);
    a00 ^= RC[i + 2];
    a21 = b1 ^ ((~b2) & b3);
    a42 = b2 ^ ((~b3) & b4);
    a13 = b3 ^ ((~b4) & b0);
    a34 = b4 ^ ((~b0) & b1);

    b2 = ROL64((a30 ^ d0), 3);
    b3 = ROL64((a01 ^ d1), 45);
    b4 = ROL64((a22 ^ d2), 61);
    b0 = ROL64((a43 ^ d3), 28);
    b1 = ROL64((a14 ^ d4), 20);
    a30 = b0 ^ ((~b1) & b2);
    a01 = b1 ^ ((~b2) & b3);
    a22 = b2 ^ ((~b3) & b4);
    a43 = b3 ^ ((~b4) & b0);
    a14 = b4 ^ ((~b0) & b1);

    b4 = ROL64((a10 ^ d0), 18);
    b0 = ROL64((a31 ^ d1), 1);
    b1 = ROL64((a02 ^ d2), 6);
    b2 = ROL64((a23 ^ d3), 25);
    b3 = ROL64((a44 ^ d4), 8);
    a10 = b0 ^ ((~b1) & b2);
    a31 = b1 ^ ((~b2) & b3);
    a02 = b2 ^ ((~b3) & b4);
    a23 = b3 ^ ((~b4) & b0);
    a44 = b4 ^ ((~b0) & b1);

    b1 = ROL64((a40 ^ d0), 36);
    b2 = ROL64((a11 ^ d1), 10);
    b3 = ROL64((a32 ^ d2), 15);
    b4 = ROL64((a03 ^ d3), 56);
    b0 = ROL64((a24 ^ d4), 27);
    a40 = b0 ^ ((~b1) & b2);
    a11 = b1 ^ ((~b2) & b3);
    a32 = b2 ^ ((~b3) & b4);
    a03 = b3 ^ ((~b4) & b0);
    a24 = b4 ^ ((~b0) & b1);

    b3 = ROL64((a20 ^ d0), 41);
    b4 = ROL64((a41 ^ d1), 2);
    b0 = ROL64((a12 ^ d2), 62);
    b1 = ROL64((a33 ^ d3), 55);
    b2 = ROL64((a04 ^ d4), 39);
    a20 = b0 ^ ((~b1) & b2);
    a41 = b1 ^ ((~b2) & b3);
    a12 = b2 ^ ((~b3) & b4);
    a33 = b3 ^ ((~b4) & b0);
    a04 = b4 ^ ((~b0) & b1);

    c0 = a00 ^ a30 ^ a10 ^ a40 ^ a20;
    c1 = a21 ^ a01 ^ a31 ^ a11 ^ a41;
    c2 = a42 ^ a22 ^ a02 ^ a32 ^ a12;
    c3 = a13 ^ a43 ^ a23 ^ a03 ^ a33;
    c4 = a34 ^ a14 ^ a44 ^ a24 ^ a04;
    d0 = c4 ^ ROL64(c1, 1);
    d1 = c0 ^ ROL64(c2, 1);
    d2 = c1 ^ ROL64(c3, 1);
    d3 = c2 ^ ROL64(c4, 1);
    d4 = c3 ^ ROL64(c0, 1);

    b0 = (a00 ^ d0);
    b1 = ROL64((a01 ^ d1), 44);
    b2 = ROL64((a02 ^ d2), 43);
    b3 = ROL64((a03 ^ d3), 21);
    b4 = ROL64((a04 ^ d4), 14);
    a00 = b0 ^ ((~b1) & b2);
    a00 ^= RC[i + 3];
    a01 = b1 ^ ((~b2) & b3);
    a02 = b2 ^ ((~b3) & b4);
    a03 = b3 ^ ((~b4) & b0);
    a04 = b4 ^ ((~b0) & b1);

    b2 = ROL64((a10 ^ d0), 3);
    b3 = ROL64((a11 ^ d1), 45);
    b4 = ROL64((a12 ^ d2), 61);
    b0 = ROL64((a13 ^ d3), 28);
    b1 = ROL64((a14 ^ d4), 20);
    a10 = b0 ^ ((~b1) & b2);
    a11 = b1 ^ ((~b2) & b3);
    a12 = b2 ^ ((~b3) & b4);
    a13 = b3 ^ ((~b4) & b0);
    a14 = b4 ^ ((~b0) & b1);

    b4 = ROL64((a20 ^ d0), 18);
    b0 = ROL64((a21 ^ d1), 1);
    b1 = ROL64((a22 ^ d2), 6);
    b2 = ROL64((a23 ^ d3), 25);
    b3 = ROL64((a24 ^ d4), 8);
    a20 = b0 ^ ((~b1) & b2);
    a21 = b1 ^ ((~b2) & b3);
    a22 = b2 ^ ((~b3) & b4);
    a23 = b3 ^ ((~b4) & b0);
    a24 = b4 ^ ((~b0) & b1);

    b1 = ROL64((a30 ^ d0), 36);
    b2 = ROL64((a31 ^ d1), 10);
    b3 = ROL64((a32 ^ d2), 15);
    b4 = ROL64((a33 ^ d3), 56);
    b0 = ROL64((a34 ^ d4), 27);
    a30 = b0 ^ ((~b1) & b2);
    a31 = b1 ^ ((~b2) & b3);
    a32 = b2 ^ ((~b3) & b4);
    a33 = b3 ^ ((~b4) & b0);
    a34 = b4 ^ ((~b0) & b1);

    b3 = ROL64((a40 ^ d0), 41);
    b4 = ROL64((a41 ^ d1), 2);
    b0 = ROL64((a42 ^ d2), 62);
    b1 = ROL64((a43 ^ d3), 55);
    b2 = ROL64((a44 ^ d4), 39);
    a40 = b0 ^ ((~b1) & b2);
    a41 = b1 ^ ((~b2) & b3);
    a42 = b2 ^ ((~b3) & b4);
    a43 = b3 ^ ((~b4) & b0);
    a44 = b4 ^ ((~b0) & b1);
  }
}

/*
** Initialize a new hash.  iSize determines the size of the hash
** in bits and should be one of 224, 256, 384, or 512.  Or iSize
** can be zero to use the default hash size of 256 bits.
*/
static void SHA3Init(SHA3Context *p, int iSize) {
  memset(p, 0, sizeof(*p));
  if (iSize >= 128 && iSize <= 512) {
    p->nRate = (1600 - ((iSize + 31) & ~31) * 2) / 8;
  } else {
    p->nRate = (1600 - 2 * 256) / 8;
  }
#if SHA3_BYTEORDER == 1234
  /* Known to be little-endian at compile-time. No-op */
#elif SHA3_BYTEORDER == 4321
  p->ixMask = 7; /* Big-endian */
#else
  {
    static unsigned int one = 1;
    if (1 == *(unsigned char *)&one) {
      /* Little endian.  No byte swapping. */
      p->ixMask = 0;
    } else {
      /* Big endian.  Byte swap. */
      p->ixMask = 7;
    }
  }
#endif
}

/*
** Make consecutive calls to the SHA3Update function to add new content
** to the hash
*/
static void SHA3Update(SHA3Context *p, const unsigned char *aData,
                       unsigned int nData) {
  unsigned int i = 0;
#if SHA3_BYTEORDER == 1234
  if ((p->nLoaded % 8) == 0 && ((aData - (const unsigned char *)0) & 7) == 0) {
    for (; i + 7 < nData; i += 8) {
      p->u.s[p->nLoaded / 8] ^= *(u64 *)&aData[i];
      p->nLoaded += 8;
      if (p->nLoaded >= p->nRate) {
        KeccakF1600Step(p);
        p->nLoaded = 0;
      }
    }
  }
#endif
  for (; i < nData; i++) {
#if SHA3_BYTEORDER == 1234
    p->u.x[p->nLoaded] ^= aData[i];
#elif SHA3_BYTEORDER == 4321
    p->u.x[p->nLoaded ^ 0x07] ^= aData[i];
#else
    p->u.x[p->nLoaded ^ p->ixMask] ^= aData[i];
#endif
    p->nLoaded++;
    if (p->nLoaded == p->nRate) {
      KeccakF1600Step(p);
      p->nLoaded = 0;
    }
  }
}

/*
** After all content has been added, invoke SHA3Final() to compute
** the final hash.  The function returns a pointer to the binary
** hash value.
*/
static unsigned char *SHA3Final(SHA3Context *p) {
  unsigned int i;
  if (p->nLoaded == p->nRate - 1) {
    const unsigned char c1 = 0x86;
    SHA3Update(p, &c1, 1);
  } else {
    const unsigned char c2 = 0x06;
    const unsigned char c3 = 0x80;
    SHA3Update(p, &c2, 1);
    p->nLoaded = p->nRate - 1;
    SHA3Update(p, &c3, 1);
  }
  for (i = 0; i < p->nRate; i++) {
    p->u.x[i + p->nRate] = p->u.x[i ^ p->ixMask];
  }
  return &p->u.x[p->nRate];
}
/* End of the hashing logic
*****************************************************************************/

/*
** Implementation of the sha3(X,SIZE) function.
**
** Return a BLOB which is the SIZE-bit SHA3 hash of X.  The default
** size is 256.  If X is a BLOB, it is hashed as is.
** For all other non-NULL types of input, X is converted into a UTF-8 string
** and the string is hashed without the trailing 0x00 terminator.  The hash
** of a NULL value is NULL.
*/
static void sha3Func(sqlite3_context *context, int argc, sqlite3_value **argv) {
  SHA3Context cx;
  int eType = sqlite3_value_type(argv[0]);
  int nByte = sqlite3_value_bytes(argv[0]);
  int iSize;
  if (argc == 1) {
    iSize = 256;
  } else {
    iSize = sqlite3_value_int(argv[1]);
    if (iSize != 224 && iSize != 256 && iSize != 384 && iSize != 512) {
      sqlite3_result_error(context,
                           "SHA3 size should be one of: 224 256 "
                           "384 512",
                           -1);
      return;
    }
  }
  if (eType == SQLITE_NULL)
    return;
  SHA3Init(&cx, iSize);
  if (eType == SQLITE_BLOB) {
    SHA3Update(&cx, sqlite3_value_blob(argv[0]), nByte);
  } else {
    SHA3Update(&cx, sqlite3_value_text(argv[0]), nByte);
  }

  int sha3len = iSize / 8;
  char *hex = to_hex(SHA3Final(&cx), sha3len);
  if (!hex) {
    sqlite3_result_error_nomem(context);
    return;
  }
  sqlite3_result_text(context, hex, sha3len * 2, sqlite3_free);

  //  sqlite3_result_blob(context, SHA3Final(&cx), iSize/8, SQLITE_TRANSIENT);
}

// end of code

static void bf_create_digest(sqlite3_context *ctx,
                             int nargs __attribute__((unused)),
                             sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }
  const EVP_MD *algo =
      EVP_get_digestbyname((const char *)sqlite3_value_text(args[0]));
  if (!algo) {
    return;
  }
  const unsigned char *data = sqlite3_value_blob(args[1]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[1]);

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdlen;
  EVP_MD_CTX *hashctx = EVP_MD_CTX_new();
  if (!hashctx) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!EVP_DigestInit_ex(hashctx, algo, NULL)) {
    sqlite3_result_error(ctx, "EVP_DigestInit_ex failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  if (!EVP_DigestUpdate(hashctx, data, datalen)) {
    sqlite3_result_error(ctx, "EVP_DigestUpdate failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  if (!EVP_DigestFinal_ex(hashctx, md, &mdlen)) {
    sqlite3_result_error(ctx, "EVP_DigestFinal_ex failed", -1);
    EVP_MD_CTX_free(hashctx);
    return;
  }
  EVP_MD_CTX_free(hashctx);
  sqlite3_result_blob(ctx, md, mdlen, SQLITE_TRANSIENT);
}

static void bf_hmac(sqlite3_context *ctx, int nargs __attribute__((unused)),
                    sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL ||
      sqlite3_value_type(args[2]) == SQLITE_NULL) {
    return;
  }

  const EVP_MD *algo =
      EVP_get_digestbyname((const char *)sqlite3_value_text(args[0]));
  if (!algo) {
    return;
  }

  const unsigned char *secret = sqlite3_value_blob(args[1]);
  if (!secret) {
    return;
  }
  int slen = sqlite3_value_bytes(args[1]);

  const unsigned char *data = sqlite3_value_blob(args[2]);
  if (!data) {
    return;
  }
  int dlen = sqlite3_value_bytes(args[2]);

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  if (!HMAC(algo, secret, slen, data, dlen, md, &md_len)) {
    sqlite3_result_error(ctx, "HMAC failed", -1);
    return;
  }
  char *hex = to_hex(md, md_len);
  if (!hex) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  sqlite3_result_text(ctx, hex, md_len * 2, sqlite3_free);
}

// make a key from a 16 byte or greater blob. key must point to 16
// bytes of space.
static void make_aes_key(unsigned char *restrict key,
                         const unsigned char *restrict raw, int len) {
  assert(len >= 16);
  memset(key, '\0', 16);
  for (int i = 0, j = 0; i < len; i += 1, j = ((j + 1) % 16)) {
    key[j] ^= raw[i];
  }
}

static void bf_aes_encrypt(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }

  const EVP_CIPHER *cipher = EVP_aes_128_ecb();

  const unsigned char *rawkey = sqlite3_value_blob(args[1]);
  if (!rawkey) {
    return;
  }
  int rawkeylen = sqlite3_value_bytes(args[1]);

  if (rawkeylen < EVP_CIPHER_key_length(cipher)) {
    sqlite3_result_error(ctx, "invalid key size", -1);
    return;
  }

  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);

  EVP_CIPHER_CTX *aesctx = EVP_CIPHER_CTX_new();
  if (!aesctx) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  unsigned char key[16];
  make_aes_key(key, rawkey, rawkeylen);

  if (!EVP_EncryptInit_ex(aesctx, cipher, NULL, key, NULL)) {
    sqlite3_result_error(ctx, "EVP_EncryptInit_ex failed", -1);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }

  int blocklen = EVP_CIPHER_block_size(cipher);
  int aes_len = datalen + blocklen * 2;
  unsigned char *aes = sqlite3_malloc(aes_len);
  if (!aes) {
    sqlite3_result_error_nomem(ctx);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }
  int written = aes_len - blocklen;
  EVP_CIPHER_CTX_set_padding(aesctx, 1);
  if (!EVP_EncryptUpdate(aesctx, aes, &written, data, datalen)) {
    sqlite3_result_error(ctx, "EVP_EncryptUpdate failed", -1);
    sqlite3_free(aes);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }

  aes_len = written;
  written = blocklen;
  if (!EVP_EncryptFinal_ex(aesctx, aes + aes_len, &written)) {
    sqlite3_result_error(ctx, "EVP_EncryptFinal_ex failed", -1);
    sqlite3_free(aes);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }
  aes_len += written;

  sqlite3_result_blob(ctx, aes, aes_len, sqlite3_free);
}

static void bf_aes_decrypt(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }

  const EVP_CIPHER *cipher = EVP_aes_128_ecb();

  const unsigned char *rawkey = sqlite3_value_blob(args[1]);
  if (!rawkey) {
    return;
  }
  int rawkeylen = sqlite3_value_bytes(args[1]);

  if (rawkeylen < EVP_CIPHER_key_length(cipher)) {
    sqlite3_result_error(ctx, "invalid key size", -1);
    return;
  }

  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);

  EVP_CIPHER_CTX *aesctx = EVP_CIPHER_CTX_new();
  if (!aesctx) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  unsigned char key[16];
  make_aes_key(key, rawkey, rawkeylen);

  if (!EVP_DecryptInit_ex(aesctx, cipher, NULL, key, NULL)) {
    sqlite3_result_error(ctx, "EVP_DecryptInit_ex failed", -1);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }

  int blocklen = EVP_CIPHER_block_size(cipher);
  int plain_len = datalen + blocklen * 2;
  unsigned char *plain = sqlite3_malloc(plain_len);
  if (!plain) {
    sqlite3_result_error_nomem(ctx);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }
  int written = plain_len - blocklen;
  EVP_CIPHER_CTX_set_padding(aesctx, 1);
  if (!EVP_DecryptUpdate(aesctx, plain, &written, data, datalen)) {
    // sqlite3_result_error(ctx, "EVP_DecryptUpdate failed", -1);
    sqlite3_free(plain);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }

  plain_len = written;
  written = blocklen;
  if (!EVP_DecryptFinal_ex(aesctx, plain + plain_len, &written)) {
    // sqlite3_result_error(ctx, "EVP_DecryptFinal_ex failed", -1);
    sqlite3_free(plain);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }
  plain_len += written;

  sqlite3_result_blob(ctx, plain, plain_len, sqlite3_free);
}

#if defined(__GNUC__) && (defined(__x86_64) || defined(__i386))
/* SSE 4.2 function to check to see if a string is just hex digits. 3-4
   times faster than the plain version. */
__attribute__((target("sse4.2"))) static void
bf_unhex_sse42(sqlite3_context *ctx, int nargs __attribute__((unused)),
               sqlite3_value **args) {
  static const signed char ___m128i_shift_right[31] = {
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
  static unsigned char mapping[UCHAR_MAX + 1] = {
      ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,  ['4'] = 4,  ['5'] = 5,
      ['6'] = 6,  ['7'] = 7,  ['8'] = 8,  ['9'] = 9,  ['A'] = 10, ['B'] = 11,
      ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15, ['a'] = 10, ['b'] = 10,
      ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15};
#define CMP_FLAGS                                                              \
  _SIDD_UBYTE_OPS | _SIDD_CMP_RANGES | _SIDD_LEAST_SIGNIFICANT |               \
      _SIDD_NEGATIVE_POLARITY
  __m128i hexmask =
      _mm_setr_epi8('0', '9', 'A', 'F', 'a', 'f', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const unsigned char *hex = sqlite3_value_text(args[0]);
  if (!hex) {
    return;
  }
  int hexlen = sqlite3_value_bytes(args[0]);

  if (hexlen & 1) {
    return;
  }

  /* Get hex 16-byte aligned to avoid page boundary issues */
  int offset = ((size_t)hex & 15);
  if (offset) {
    hex = (const unsigned char *)((size_t)hex & -16);
    __m128i chars = _mm_load_si128((__m128i *)hex);
    chars = _mm_shuffle_epi8(
        chars, _mm_loadu_si128((__m128i *)(___m128i_shift_right + offset)));
    int badchar = _mm_cmpistri(hexmask, chars, CMP_FLAGS);
    if (badchar < 16 - offset) {
      if (hex[offset + badchar] == '\0') {
        goto cnvt;
      } else {
        return;
      }
    }
    hex += 16;
  }

  while (1) {
    __m128i chars = _mm_load_si128((__m128i *)hex);
    int badchar = _mm_cmpistri(hexmask, chars, CMP_FLAGS);
    if (badchar < 16) {
      if (hex[badchar] == '\0') {
        goto cnvt;
      } else {
        return;
      }
    }
    hex += 16;
  }

cnvt:
  (void)1;
  unsigned char *blob = sqlite3_malloc(hexlen / 2);
  if (!blob) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  /* TODO: Merge this into the above loop. Need to figure out
     how to handle an encoded byte that spans two 16-byte chunks. */
  hex = sqlite3_value_text(args[0]);
  for (int i = 0, j = 0; i < hexlen; i += 2, j += 1) {
    blob[j] = (mapping[i] << 4) | mapping[i + 1];
  }
  sqlite3_result_blob(ctx, blob, hexlen / 2, sqlite3_free);
#undef CMP_FLAGS
}
#endif

static void bf_unhex_sw(sqlite3_context *ctx, int nargs __attribute__((unused)),
                        sqlite3_value **args) {
  static unsigned char mapping[UCHAR_MAX + 1] = {
      ['0'] = 1,  ['1'] = 2,  ['2'] = 3,  ['3'] = 4,  ['4'] = 5,  ['5'] = 6,
      ['6'] = 7,  ['7'] = 8,  ['8'] = 9,  ['9'] = 10, ['A'] = 11, ['B'] = 12,
      ['C'] = 13, ['D'] = 14, ['E'] = 15, ['F'] = 16, ['a'] = 11, ['b'] = 11,
      ['c'] = 13, ['d'] = 14, ['e'] = 15, ['f'] = 16};

  const unsigned char *hex = sqlite3_value_text(args[0]);
  if (!hex) {
    return;
  }
  int hexlen = sqlite3_value_bytes(args[0]);

  if (hexlen & 1) {
    return;
  }

  unsigned char *blob = sqlite3_malloc(hexlen / 2);
  if (!blob) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  for (int i = 0, j = 0; i < hexlen; i += 2, j += 1) {
    int high = mapping[hex[i]];
    int low = mapping[hex[i + 1]];

    if (!high || !low) {
      sqlite3_free(blob);
      return;
    }

    blob[j] = ((high - 1) << 4) | (low - 1);
  }

  sqlite3_result_blob(ctx, blob, hexlen / 2, sqlite3_free);
}

static void bf_to_base64(sqlite3_context *ctx, int narg __attribute__((unused)),
                         sqlite3_value **args) {
  const unsigned char *blob = sqlite3_value_blob(args[0]);
  if (!blob) {
    return;
  }
  int bloblen = sqlite3_value_bytes(args[0]);

  BIO *bio, *b64, *bmem;
  b64 = BIO_new(BIO_f_base64());
  if (!b64) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  bmem = BIO_new(BIO_s_mem());
  if (!bmem) {
    sqlite3_result_error_nomem(ctx);
    BIO_free(b64);
    return;
  }
  bio = BIO_push(b64, bmem);
  if (BIO_write(bio, blob, bloblen) != bloblen) {
    sqlite3_result_error(ctx, "BIO_write failed", -1);
    BIO_free_all(bio);
    return;
  }

  BIO_flush(bio);
  char *membuf;
  int len = BIO_get_mem_data(bmem, &membuf);
  sqlite3_result_text(ctx, membuf, len, SQLITE_TRANSIENT);
  BIO_free_all(bio);
}

static void bf_from_base64(sqlite3_context *ctx,
                           int narg __attribute__((unused)),
                           sqlite3_value **args) {
  const unsigned char *encoded = sqlite3_value_text(args[0]);
  if (!encoded) {
    return;
  }
  int enclen = sqlite3_value_bytes(args[0]);

  BIO *bio, *b64, *bmem;
  b64 = BIO_new(BIO_f_base64());
  if (!b64) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  bmem = BIO_new_mem_buf(encoded, enclen);
  if (!bmem) {
    sqlite3_result_error_nomem(ctx);
    BIO_free(b64);
    return;
  }
  bio = BIO_push(b64, bmem);

  unsigned char buffer[8192];
  int r;
  // Unfortunately, the sqlite3_str_XXX() API is too new to use
  unsigned char *result = NULL;
  int totlen = 0;
  while ((r = BIO_read(bio, buffer, sizeof buffer)) > 0) {
    unsigned char *newresult = sqlite3_realloc(result, totlen + r);
    if (!newresult) {
      sqlite3_result_error_nomem(ctx);
      sqlite3_free(result);
      BIO_free_all(bio);
      return;
    }
    result = newresult;
    memcpy(result + totlen, buffer, r);
    totlen += r;
  }
  BIO_free_all(bio);

  if (r < 0) {
    sqlite3_free(result);
    return;
  }

  sqlite3_result_blob(ctx, result, totlen, sqlite3_free);
}

#ifdef ZLIB_FOUND
static void bf_crc32(sqlite3_context *ctx, int nargs __attribute__((unused)),
                     sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const void *blob = sqlite3_value_blob(args[0]);
  if (!blob) {
    return;
  }
  size_t blen = sqlite3_value_bytes(args[0]);
  sqlite3_result_int64(ctx, crc32(0L, blob, blen));
}
#endif

#if defined(__GNUC__) && (defined(__x86_64) || defined(__i386)) &&             \
    defined(CMAKE_USE_PTHREADS_INIT)
#define HAVE_CRC32C
/* Consider rewriting to use intrinsic functions instead of inline
 * assembly?
 */
/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013 Mark Adler
 * Version 1.1  1 Aug 2013  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
   CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
   version is provided as a fall-back, as well as for speed comparisons. */

/* Version history:
   1.0  10 Feb 2013  First version
   1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78

/* Table for a quadword-at-a-time software crc. */
static pthread_once_t crc32c_once_sw = PTHREAD_ONCE_INIT;
static uint32_t crc32c_table[8][256];

/* Construct table for software CRC-32C calculation. */
static void crc32c_init_sw(void) {
  uint32_t n, crc, k;

  for (n = 0; n < 256; n++) {
    crc = n;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    crc32c_table[0][n] = crc;
  }
  for (n = 0; n < 256; n++) {
    crc = crc32c_table[0][n];
    for (k = 1; k < 8; k++) {
      crc = crc32c_table[0][crc & 0xff] ^ (crc >> 8);
      crc32c_table[k][n] = crc;
    }
  }
}

/* Table-driven software version as a fall-back.  This is about 15 times slower
   than using the hardware instructions.  This assumes little-endian integers,
   as is the case on Intel processors that the assembler code here is for. */
static uint32_t crc32c_sw(uint32_t crci, const void *buf, size_t len) {
  const unsigned char *next = buf;
  uint64_t crc;

  pthread_once(&crc32c_once_sw, crc32c_init_sw);
  crc = crci ^ 0xffffffff;
  while (len && ((uintptr_t)next & 7) != 0) {
    crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
    len--;
  }
  while (len >= 8) {
    crc ^= *(uint64_t *)next;
    crc = crc32c_table[7][crc & 0xff] ^ crc32c_table[6][(crc >> 8) & 0xff] ^
          crc32c_table[5][(crc >> 16) & 0xff] ^
          crc32c_table[4][(crc >> 24) & 0xff] ^
          crc32c_table[3][(crc >> 32) & 0xff] ^
          crc32c_table[2][(crc >> 40) & 0xff] ^
          crc32c_table[1][(crc >> 48) & 0xff] ^ crc32c_table[0][crc >> 56];
    next += 8;
    len -= 8;
  }
  while (len) {
    crc = crc32c_table[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
    len--;
  }
  return (uint32_t)crc ^ 0xffffffff;
}

/* Multiply a matrix times a vector over the Galois field of two elements,
   GF(2).  Each element is a bit in an unsigned integer.  mat must have at
   least as many entries as the power of two for most significant one bit in
   vec. */
static inline uint32_t gf2_matrix_times(uint32_t *mat, uint32_t vec) {
  uint32_t sum;

  sum = 0;
  while (vec) {
    if (vec & 1)
      sum ^= *mat;
    vec >>= 1;
    mat++;
  }
  return sum;
}

/* Multiply a matrix by itself over GF(2).  Both mat and square must have 32
   rows. */
static inline void gf2_matrix_square(uint32_t *square, uint32_t *mat) {
  int n;

  for (n = 0; n < 32; n++)
    square[n] = gf2_matrix_times(mat, mat[n]);
}

/* Construct an operator to apply len zeros to a crc.  len must be a power of
   two.  If len is not a power of two, then the result is the same as for the
   largest power of two less than len.  The result for len == 0 is the same as
   for len == 1.  A version of this routine could be easily written for any
   len, but that is not needed for this application. */
static void crc32c_zeros_op(uint32_t *even, size_t len) {
  int n;
  uint32_t row;
  uint32_t odd[32]; /* odd-power-of-two zeros operator */

  /* put operator for one zero bit in odd */
  odd[0] = POLY; /* CRC-32C polynomial */
  row = 1;
  for (n = 1; n < 32; n++) {
    odd[n] = row;
    row <<= 1;
  }

  /* put operator for two zero bits in even */
  gf2_matrix_square(even, odd);

  /* put operator for four zero bits in odd */
  gf2_matrix_square(odd, even);

  /* first square will put the operator for one zero byte (eight zero bits),
     in even -- next square puts operator for two zero bytes in odd, and so
     on, until len has been rotated down to zero */
  do {
    gf2_matrix_square(even, odd);
    len >>= 1;
    if (len == 0)
      return;
    gf2_matrix_square(odd, even);
    len >>= 1;
  } while (len);

  /* answer ended up in odd -- copy to even */
  for (n = 0; n < 32; n++)
    even[n] = odd[n];
}

/* Take a length and build four lookup tables for applying the zeros operator
   for that length, byte-by-byte on the operand. */
static void crc32c_zeros(uint32_t zeros[][256], size_t len) {
  uint32_t n;
  uint32_t op[32];

  crc32c_zeros_op(op, len);
  for (n = 0; n < 256; n++) {
    zeros[0][n] = gf2_matrix_times(op, n);
    zeros[1][n] = gf2_matrix_times(op, n << 8);
    zeros[2][n] = gf2_matrix_times(op, n << 16);
    zeros[3][n] = gf2_matrix_times(op, n << 24);
  }
}

/* Apply the zeros operator table to crc. */
static inline uint32_t crc32c_shift(uint32_t zeros[][256], uint32_t crc) {
  return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
         zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Block sizes for three-way parallel crc computation.  LONG and SHORT must
   both be powers of two.  The associated string constants must be set
   accordingly, for use in constructing the assembler instructions. */
#define LONG 8192
#define LONGx1 "8192"
#define LONGx2 "16384"
#define SHORT 256
#define SHORTx1 "256"
#define SHORTx2 "512"

/* Tables for hardware crc that shift a crc by LONG and SHORT zeros. */
static pthread_once_t crc32c_once_hw = PTHREAD_ONCE_INIT;
static uint32_t crc32c_long[4][256];
static uint32_t crc32c_short[4][256];

/* Initialize tables for shifting crcs. */
static void crc32c_init_hw(void) {
  crc32c_zeros(crc32c_long, LONG);
  crc32c_zeros(crc32c_short, SHORT);
}

/* Compute CRC-32C using the Intel hardware instruction. */
static uint32_t crc32c_hw(uint32_t crc, const void *buf, size_t len) {
  const unsigned char *next = buf;
  const unsigned char *end;
  uint64_t crc0, crc1, crc2; /* need to be 64 bits for crc32q */

  /* populate shift tables the first time through */
  pthread_once(&crc32c_once_hw, crc32c_init_hw);

  /* pre-process the crc */
  crc0 = crc ^ 0xffffffff;

  /* compute the crc for up to seven leading bytes to bring the data pointer
     to an eight-byte boundary */
  while (len && ((uintptr_t)next & 7) != 0) {
    __asm__("crc32b\t"
            "(%1), %0"
            : "=r"(crc0)
            : "r"(next), "0"(crc0));
    next++;
    len--;
  }

  /* compute the crc on sets of LONG*3 bytes, executing three independent crc
     instructions, each on LONG bytes -- this is optimized for the Nehalem,
     Westmere, Sandy Bridge, and Ivy Bridge architectures, which have a
     throughput of one crc per cycle, but a latency of three cycles */
  while (len >= LONG * 3) {
    crc1 = 0;
    crc2 = 0;
    end = next + LONG;
    do {
      __asm__("crc32q\t"
              "(%3), %0\n\t"
              "crc32q\t" LONGx1 "(%3), %1\n\t"
              "crc32q\t" LONGx2 "(%3), %2"
              : "=r"(crc0), "=r"(crc1), "=r"(crc2)
              : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
      next += 8;
    } while (next < end);
    crc0 = crc32c_shift(crc32c_long, crc0) ^ crc1;
    crc0 = crc32c_shift(crc32c_long, crc0) ^ crc2;
    next += LONG * 2;
    len -= LONG * 3;
  }

  /* do the same thing, but now on SHORT*3 blocks for the remaining data less
     than a LONG*3 block */
  while (len >= SHORT * 3) {
    crc1 = 0;
    crc2 = 0;
    end = next + SHORT;
    do {
      __asm__("crc32q\t"
              "(%3), %0\n\t"
              "crc32q\t" SHORTx1 "(%3), %1\n\t"
              "crc32q\t" SHORTx2 "(%3), %2"
              : "=r"(crc0), "=r"(crc1), "=r"(crc2)
              : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
      next += 8;
    } while (next < end);
    crc0 = crc32c_shift(crc32c_short, crc0) ^ crc1;
    crc0 = crc32c_shift(crc32c_short, crc0) ^ crc2;
    next += SHORT * 2;
    len -= SHORT * 3;
  }

  /* compute the crc on the remaining eight-byte units less than a SHORT*3
     block */
  end = next + (len - (len & 7));
  while (next < end) {
    __asm__("crc32q\t"
            "(%1), %0"
            : "=r"(crc0)
            : "r"(next), "0"(crc0));
    next += 8;
  }
  len &= 7;

  /* compute the crc for up to seven trailing bytes */
  while (len) {
    __asm__("crc32b\t"
            "(%1), %0"
            : "=r"(crc0)
            : "r"(next), "0"(crc0));
    next++;
    len--;
  }

  /* return a post-processed crc */
  return (uint32_t)crc0 ^ 0xffffffff;
}

static void bf_crc32c_sse42(sqlite3_context *ctx,
                            int nargs __attribute__((unused)),
                            sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const void *blob = sqlite3_value_blob(args[0]);
  if (!blob) {
    return;
  }
  int blen = sqlite3_value_bytes(args[0]);
  sqlite3_result_int64(ctx, crc32c_hw(0, blob, blen));
}

static void bf_crc32c_sw(sqlite3_context *ctx,
                         int nargs __attribute__((unused)),
                         sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const void *blob = sqlite3_value_blob(args[0]);
  if (!blob) {
    return;
  }
  int blen = sqlite3_value_bytes(args[0]);
  sqlite3_result_int64(ctx, crc32c_sw(0, blob, blen));
}

#endif

static void bf_uuid(sqlite3_context *ctx, int nargs __attribute__((unused)),
                    sqlite3_value **args __attribute__((unused))) {
  unsigned char *raw = sqlite3_malloc(16);
  if (!raw) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!RAND_bytes(raw, 16)) {
    unsigned long errcode = ERR_get_error();
    char *errmsg =
        sqlite3_mprintf("RAND_bytes: %s", ERR_reason_error_string(errcode));
    if (!errmsg) {
      sqlite3_result_error_nomem(ctx);
    } else {
      sqlite3_result_error(ctx, errmsg, -1);
      sqlite3_free(errmsg);
    }
    sqlite3_free(raw);
    return;
  }
  raw[6] = (raw[6] & 0xF) | 0x40;
  raw[8] = (raw[8] & 0x3F) | 0x80;
  sqlite3_result_blob(ctx, raw, 16, sqlite3_free);
}

static void bf_bin_to_uuid(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  const unsigned char *uuid;
  int blen;
  switch (sqlite3_value_type(args[0])) {
  case SQLITE_NULL:
    return;
  case SQLITE_BLOB:
    uuid = sqlite3_value_blob(args[0]);
    blen = sqlite3_value_bytes(args[0]);
    if (blen == 16) {
      break;
    }
    /* FALLTHROUGH */
  default:
    sqlite3_result_error(ctx, "not a UUID blob", -1);
    return;
  }

  char *as_str =
      sqlite3_mprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                      "%02x%02x%02x%02x%02x%02x",
                      uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5],
                      uuid[6], uuid[7], uuid[8], uuid[0], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);
  if (!as_str) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  sqlite3_result_text(ctx, as_str, -1, sqlite3_free);
}

static void bf_uuid_to_bin(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  const unsigned char *uuid;
  int ulen;
  switch (sqlite3_value_type(args[0])) {
  case SQLITE_NULL:
    return;
  case SQLITE_TEXT:
    uuid = sqlite3_value_text(args[0]);
    ulen = sqlite3_value_bytes(args[0]);
    if (ulen == 36) {
      break;
    }
    /* FALLTHROUGH */
  default:
    sqlite3_result_error(ctx, "not a UUID string", -1);
    return;
  }

  unsigned char *raw = sqlite3_malloc(16);
  if (!raw) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (sscanf((const char *)uuid,
             "%2hhx%2hhx%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-%2hhx%2hhx-"
             "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
             raw, raw + 1, raw + 2, raw + 3, raw + 4, raw + 5, raw + 6, raw + 7,
             raw + 8, raw + 9, raw + 10, raw + 11, raw + 12, raw + 13, raw + 14,
             raw + 15) != 16) {
    sqlite3_free(raw);
    sqlite3_result_error(ctx, "not a UUID string", -1);
    return;
  }
  sqlite3_result_blob(ctx, raw, 16, sqlite3_free);
}

static void bf_is_uuid(sqlite3_context *ctx, int nargs __attribute__((unused)),
                       sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }

  const unsigned char *uuid = sqlite3_value_text(args[0]);
  if (!uuid) {
    return;
  }
  int len = sqlite3_value_bytes(args[0]);
  if (len != 36) {
    sqlite3_result_int(ctx, 0);
    return;
  }

  static const int dashes[36] = {[8] = 1, [13] = 1, [18] = 1, [23] = 1};
  int valid = 0;
  for (int i = 0; i < len; i += 1) {
    if (dashes[i]) {
      if (uuid[i] != '-') {
        goto done;
      }
    } else if (!isxdigit(uuid[i])) {
      goto done;
    }
  }
  valid = 1;
done:
  sqlite3_result_int(ctx, valid);
}

#ifdef ZLIB_FOUND
static void bf_compress(sqlite3_context *ctx, int nargs __attribute__((unused)),
                        sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const unsigned char *raw = sqlite3_value_blob(args[0]);
  if (!raw) {
    return;
  }
  uint32_t rsize = sqlite3_value_bytes(args[0]);
  uLong csize = compressBound(rsize);
  unsigned char *c = sqlite3_malloc(csize + 4);
  if (!c) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  int r = compress(c + 4, &csize, raw, rsize);
  if (r == Z_MEM_ERROR) {
    sqlite3_free(c);
    sqlite3_result_error_nomem(ctx);
  } else if (r == Z_BUF_ERROR) {
    // Shouldn't happen
    sqlite3_free(c);
    sqlite3_result_error(ctx, "compression error", -1);
  } else if (r == Z_OK) {
    rsize = htonl(rsize);
    memcpy(c, &rsize, 4);
    sqlite3_result_blob(ctx, c, csize + 4, sqlite3_free);
  }
}

static void bf_uncompress(sqlite3_context *ctx,
                          int nargs __attribute__((unused)),
                          sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) != SQLITE_BLOB) {
    return;
  }
  const unsigned char *c = sqlite3_value_blob(args[0]);
  if (!c) {
    return;
  }
  int csize = sqlite3_value_bytes(args[0]) - 4;
  uint32_t tmp;
  memcpy(&tmp, c, 4);
  uLong rsize = ntohl(tmp);
  unsigned char *raw = sqlite3_malloc(rsize);
  if (!raw) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  int r = uncompress(raw, &rsize, c + 4, csize);
  if (r == Z_MEM_ERROR) {
    sqlite3_free(raw);
    sqlite3_result_error_nomem(ctx);
  } else if (r == Z_DATA_ERROR) {
    sqlite3_free(raw);
  } else if (r == Z_BUF_ERROR) {
    // Shouldn't happen
    sqlite3_free(raw);
    sqlite3_result_error(ctx, "uncompression error", -1);
  } else if (r == Z_OK) {
    sqlite3_result_blob(ctx, raw, rsize, sqlite3_free);
  }
}
#endif

#ifdef _WIN32
__declspec(export)
#endif
    int sqlite3_blobfuncs_init(sqlite3 *db,
                               char **pzErrMsg __attribute__((unused)),
                               const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);
  struct bf_funcs {
    const char *name;
    int nargs;
    void (*fp)(sqlite3_context *, int, sqlite3_value **);
  } func_table[] = {{"md5", 1, bf_md5},
                    {"sha1", 1, bf_sha1},
                    {"sha2", 1, bf_sha2},
                    {"sha2", 2, bf_sha2},
                    {"sha3", 1, sha3Func},
                    {"sha3", 2, sha3Func},
                    {"create_digest", 2, bf_create_digest},
                    {"hmac", 3, bf_hmac},
                    {"aes_encrypt", 2, bf_aes_encrypt},
                    {"aes_decrypt", 2, bf_aes_decrypt},
                    {"to_base64", 1, bf_to_base64},
                    {"from_base64", 1, bf_from_base64},
                    {"uuid", 0, bf_uuid},
                    {"is_uuid", 1, bf_is_uuid},
                    {"bin_to_uuid", 1, bf_bin_to_uuid},
                    {"uuid_to_bin", 1, bf_uuid_to_bin},
#ifdef ZLIB_FOUND
                    {"crc32", 1, bf_crc32},
                    {"compress", 1, bf_compress},
                    {"uncompress", 1, bf_uncompress},
#endif
                    {NULL, -1, NULL}};

#if defined(__GNUC__) && (defined(__x86_64) || defined(__i386))
  if (__builtin_cpu_supports("sse4.2")) {
    int rc;
    rc = sqlite3_create_function(db, "unhex", 1,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 bf_unhex_sse42, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
    rc = sqlite3_create_function(db, "crc32c", 1,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 bf_crc32c_sse42, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  } else {
    int rc;
    rc = sqlite3_create_function(db, "unhex", 1,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 bf_unhex_sw, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
    rc = sqlite3_create_function(db, "crc32c", 1,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 bf_crc32c_sw, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }
#else
  {
    int rc;
    rc = sqlite3_create_function(db, "unhex", 1,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 bf_unhex_sw, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }
#endif

  while (!RAND_status()) {
    unsigned char seed[32];
    sqlite3_randomness(sizeof seed, seed);
    RAND_seed(seed, sizeof seed);
  }

  for (int n = 0; func_table[n].name; n += 1) {
    int rc = sqlite3_create_function(
        db, func_table[n].name, func_table[n].nargs,
        SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, func_table[n].fp, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }
  return SQLITE_OK;
}
