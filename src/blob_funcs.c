
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sqlite3ext.h>
#include <string.h>

#include "config.h"

SQLITE_EXTENSION_INIT1

static char *to_hex(const unsigned char *bytes, int len) {
  static const char hexdigits[] = "0123456789abcdef";
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
  if (sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }
  const unsigned char *data = sqlite3_value_blob(args[0]);
  if (!data) {
    return;
  }
  int datalen = sqlite3_value_bytes(args[0]);
  const EVP_MD *algo = get_sha2_algo(sqlite3_value_int(args[1]));
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
    return;
  }
  if (!EVP_DigestUpdate(hashctx, data, datalen)) {
    sqlite3_result_error(ctx, "EVP_DigestUpdate failed", -1);
    return;
  }
  if (!EVP_DigestFinal_ex(hashctx, md, &mdlen)) {
    sqlite3_result_error(ctx, "EVP_DigestFinal_ex failed", -1);
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

static void bf_hmac(sqlite3_context *ctx, int nargs, sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }

  const EVP_MD *algo = get_sha2_algo(sqlite3_value_int(args[0]));
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

static void bf_aes_encrypt(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  const EVP_CIPHER *cipher = EVP_aes_128_ecb();

  const unsigned char *key = sqlite3_value_blob(args[1]);
  if (!key) {
    return;
  }
  int keylen = sqlite3_value_bytes(args[1]);

  if (keylen != EVP_CIPHER_key_length(cipher)) {
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
  const EVP_CIPHER *cipher = EVP_aes_128_ecb();

  const unsigned char *key = sqlite3_value_blob(args[1]);
  if (!key) {
    return;
  }
  int keylen = sqlite3_value_bytes(args[1]);

  if (keylen != EVP_CIPHER_key_length(cipher)) {
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
    sqlite3_result_error(ctx, "EVP_DecryptUpdate failed", -1);
    sqlite3_free(plain);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }

  plain_len = written;
  written = blocklen;
  if (!EVP_DecryptFinal_ex(aesctx, plain + plain_len, &written)) {
    sqlite3_result_error(ctx, "EVP_DecryptFinal_ex failed", -1);
    sqlite3_free(plain);
    EVP_CIPHER_CTX_free(aesctx);
    return;
  }
  plain_len += written;

  sqlite3_result_blob(ctx, plain, plain_len, sqlite3_free);
}

static unsigned hexchar_to_int(unsigned char c) {
  switch (c) {
  case '0':
  case '1':
  case '2':
  case '3':
  case '4':
  case '5':
  case '6':
  case '7':
  case '8':
  case '9':
    return c - '0';
  case 'A':
  case 'a':
    return 10;
  case 'B':
  case 'b':
    return 11;
  case 'C':
  case 'c':
    return 12;
  case 'D':
  case 'd':
    return 13;
  case 'E':
  case 'e':
    return 14;
  case 'F':
  case 'f':
    return 15;
  default: /* Shouldn't be reached */
    return 0xFF;
  }
}

static void bf_unhex(sqlite3_context *ctx, int nargs __attribute__((unused)),
                     sqlite3_value **args) {
  const unsigned char *hex = sqlite3_value_text(args[0]);
  if (!hex) {
    return;
  }
  int hexlen = sqlite3_value_bytes(args[0]);

  if (hexlen & 1) {
    return;
  }

  if (strspn(hex, "0123456789ABCDEFabcdef") != (size_t)hexlen) {
    return;
  }

  unsigned char *blob = sqlite3_malloc(hexlen / 2);
  if (!blob) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  int i = 0;
  for (int n = 0; n < hexlen; n += 2) {
    blob[i++] = (hexchar_to_int(hex[n]) << 4) + hexchar_to_int(hex[n + 1]);
  }
  sqlite3_result_blob(ctx, blob, i, sqlite3_free);
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
  // Unfortunately, the sqlite3_str_XXX() API is too new to use */
  unsigned char *result = NULL;
  int totlen = 0;
  while ((r = BIO_read(bio, buffer, sizeof buffer)) > 0) {
    char *newresult = sqlite3_realloc(result, totlen + r);
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

/*-
 *  COPYRIGHT (C) 1986 Gary S. Brown.  You may use this program, or
 *  code or tables extracted from it, as desired without restriction.
 *
 *  First, the polynomial itself and its table of feedback terms.  The
 *  polynomial is
 *  X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X^1+X^0
 *
 *  Note that we take it "backwards" and put the highest-order term in
 *  the lowest-order bit.  The X^32 term is "implied"; the LSB is the
 *  X^31 term, etc.  The X^0 term (usually shown as "+1") results in
 *  the MSB being 1
 *
 *  Note that the usual hardware shift register implementation, which
 *  is what we're using (we're merely optimizing it by doing eight-bit
 *  chunks at a time) shifts bits into the lowest-order term.  In our
 *  implementation, that means shifting towards the right.  Why do we
 *  do it this way?  Because the calculated CRC must be transmitted in
 *  order from highest-order term to lowest-order term.  UARTs transmit
 *  characters in order from LSB to MSB.  By storing the CRC this way
 *  we hand it to the UART in the order low-byte to high-byte; the UART
 *  sends each low-bit to hight-bit; and the result is transmission bit
 *  by bit from highest- to lowest-order term without requiring any bit
 *  shuffling on our part.  Reception works similarly
 *
 *  The feedback terms table consists of 256, 32-bit entries.  Notes
 *
 *      The table can be generated at runtime if desired; code to do so
 *      is shown later.  It might not be obvious, but the feedback
 *      terms simply represent the results of eight shift/xor opera
 *      tions for all combinations of data and CRC register values
 *
 *      The values must be right-shifted by eight bits by the "updcrc
 *      logic; the shift must be unsigned (bring in zeroes).  On some
 *      hardware you could probably optimize the shift in assembler by
 *      using byte-swap instructions
 *      polynomial $edb88320
 *
 *
 * CRC32 code derived from work by Gary S. Brown.
 */

static uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

static uint32_t crc32(uint32_t crc, const void *buf, size_t size) {
  const uint8_t *p;

  p = buf;
  crc = crc ^ ~0U;

  while (size--)
    crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

  return crc ^ ~0U;
}

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
  sqlite3_result_int64(ctx, crc32(0, blob, blen));
}

#if defined(__GNUC__) && (defined(__x86_64) || defined(__i386)) &&             \
    defined(CMAKE_USE_PTHREADS_INIT)
#define HAVE_CRC32C
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

/* Check for SSE 4.2.  SSE 4.2 was first supported in Nehalem processors
   introduced in November, 2008.  This does not check for the existence of the
   cpuid instruction itself, which was introduced on the 486SL in 1992, so this
   will fail on earlier x86 processors.  cpuid works on all Pentium and later
   processors. */
#define SSE42(have)                                                            \
  do {                                                                         \
    uint32_t eax, ecx;                                                         \
    eax = 1;                                                                   \
    __asm__("cpuid" : "=c"(ecx) : "a"(eax) : "%ebx", "%edx");                  \
    (have) = (ecx >> 20) & 1;                                                  \
  } while (0)

/* Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
   version.  Otherwise, use the software version. */
uint32_t crc32c(uint32_t crc, const void *buf, size_t len) {
  static int sse42 = -1;

  if (sse42 < 0) {
    SSE42(sse42);
  }
  return sse42 > 1 ? crc32c_hw(crc, buf, len) : crc32c_sw(crc, buf, len);
}

static void bf_crc32c(sqlite3_context *ctx, int nargs __attribute__((unused)),
                      sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  const void *blob = sqlite3_value_blob(args[0]);
  if (!blob) {
    return;
  }
  int blen = sqlite3_value_bytes(args[0]);
  sqlite3_result_int64(ctx, crc32c(0, blob, blen));
}

#endif

static void bf_uuid(sqlite3_context *ctx, int nargs __attribute__((unused)),
                    sqlite3_value **args __attribute__((unused))) {
  unsigned char *raw = sqlite3_malloc(16);
  if (!raw) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  sqlite3_randomness(16, raw);
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
  if (sscanf(uuid,
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
                    {"sha2", 2, bf_sha2},
                    {"hmac_sha2", 3, bf_hmac},
                    {"aes_encrypt", 2, bf_aes_encrypt},
                    {"aes_decrypt", 2, bf_aes_decrypt},
                    {"unhex", 1, bf_unhex},
                    {"to_base64", 1, bf_to_base64},
                    {"from_base64", 1, bf_from_base64},
                    {"crc32", 1, bf_crc32},
#ifdef HAVE_CRC32C
                    {"crc32c", 1, bf_crc32c},
#endif
                    {"uuid", 0, bf_uuid},
                    {"bin_to_uuid", 1, bf_bin_to_uuid},
                    {"uuid_to_bin", 1, bf_uuid_to_bin},
                    {NULL, -1, NULL}};

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
