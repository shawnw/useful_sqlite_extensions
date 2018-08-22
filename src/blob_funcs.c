
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sqlite3ext.h>
#include <string.h>

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
