/* PCRE2 regexp support */

#include <stdio.h>

#include "config.h"
#include <sqlite3ext.h>
#include <stdbool.h>

#if defined(HAVE_PCRE2_8) || defined(HAVE_PCRE2_16)
#define PCRE2_CODE_UNIT_WIDTH 0
#include <pcre2.h>
#endif

SQLITE_EXTENSION_INIT1

#ifdef HAVE_PCRE2_8

struct re_cache8 {
  pcre2_code_8 *re;
  pcre2_match_data_8 *md;
};

static void re_delete8(void *v) {
  struct re_cache8 *c = v;
  pcre2_code_free_8(c->re);
  pcre2_match_data_free_8(c->md);
  sqlite3_free(c);
}

void re_regexp8(sqlite3_context *ctx, int nargs __attribute__((unused)),
                sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }

  struct re_cache8 *c = sqlite3_get_auxdata(ctx, 0);
  if (!c) {
    int errcode;
    PCRE2_SIZE erroffset;
    c = sqlite3_malloc(sizeof *c);
    if (!c) {
      sqlite3_result_error_nomem(ctx);
      return;
    }
    printf("Compiling '%s'\n", sqlite3_value_text(args[0]));
    c->re = pcre2_compile_8(
        sqlite3_value_text(args[0]), sqlite3_value_bytes(args[0]),
        PCRE2_ANCHORED | PCRE2_ENDANCHORED | PCRE2_UTF | PCRE2_UCP, &errcode,
        &erroffset, NULL);
    if (!c->re) {
      PCRE2_UCHAR8 errstr[120];
      sqlite3_free(c);
      pcre2_get_error_message_8(errcode, errstr, sizeof errstr);
      sqlite3_result_error(ctx, errstr, -1);
      return;
    }
    pcre2_jit_compile_8(c->re, PCRE2_JIT_COMPLETE);
    c->md = pcre2_match_data_create_from_pattern_8(c->re, NULL);
    sqlite3_set_auxdata(ctx, 0, c, re_delete8);
  }

  int m = pcre2_match_8(c->re, sqlite3_value_text(args[1]),
                        sqlite3_value_bytes(args[1]), 0, 0, c->md, NULL);
  sqlite3_result_int(ctx, m >= 0);
}

void re_version8(sqlite3_context *ctx, int nargs __attribute__((unused)),
                 sqlite3_value **args __attribute__((unused))) {
  PCRE2_UCHAR8 vers[24];
  pcre2_config_8(PCRE2_CONFIG_VERSION, vers);
  sqlite3_result_text(ctx, vers, -1, SQLITE_TRANSIENT);
}

void re_unicode8(sqlite3_context *ctx, int nargs __attribute__((unused)),
                 sqlite3_value **args __attribute__((unused))) {
  PCRE2_UCHAR8 vers[24];
  pcre2_config_8(PCRE2_CONFIG_UNICODE_VERSION, vers);
  sqlite3_result_text(ctx, vers, -1, SQLITE_TRANSIENT);
}
#endif

#ifdef HAVE_PCRE2_16

struct re_cache16 {
  pcre2_code_16 *re;
  pcre2_match_data_16 *md;
};

static void re_delete16(void *v) {
  struct re_cache16 *c = v;
  pcre2_code_free_16(c->re);
  pcre2_match_data_free_16(c->md);
  sqlite3_free(c);
}

void re_regexp16(sqlite3_context *ctx, int nargs __attribute__((unused)),
                 sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }

  struct re_cache16 *c = sqlite3_get_auxdata(ctx, 0);
  if (!c) {
    int errcode;
    PCRE2_SIZE erroffset;
    c = sqlite3_malloc(sizeof *c);
    if (!c) {
      sqlite3_result_error_nomem(ctx);
      return;
    }

    c->re = pcre2_compile_16(
        sqlite3_value_text16(args[0]), sqlite3_value_bytes16(args[0]) / 2,
        PCRE2_ANCHORED | PCRE2_ENDANCHORED | PCRE2_UTF | PCRE2_UCP, &errcode,
        &erroffset, NULL);
    if (!c->re) {
      PCRE2_UCHAR16 errstr[120];
      sqlite3_free(c);
      pcre2_get_error_message_16(errcode, errstr, sizeof errstr / 2);
      sqlite3_result_error16(ctx, errstr, -1);
      return;
    }
    pcre2_jit_compile_16(c->re, PCRE2_JIT_COMPLETE);
    c->md = pcre2_match_data_create_from_pattern_16(c->re, NULL);
    sqlite3_set_auxdata(ctx, 0, c, re_delete16);
  }

  int m = pcre2_match_16(c->re, sqlite3_value_text16(args[1]),
                         sqlite3_value_bytes16(args[1]) / 2, 0, 0, c->md, NULL);
  sqlite3_result_int(ctx, m >= 0);
}

void re_version16(sqlite3_context *ctx, int nargs __attribute__((unused)),
                  sqlite3_value **args __attribute__((unused))) {
  PCRE2_UCHAR16 vers[24];
  pcre2_config_16(PCRE2_CONFIG_VERSION, vers);
  sqlite3_result_text16(ctx, vers, -1, SQLITE_TRANSIENT);
}

void re_unicode16(sqlite3_context *ctx, int nargs __attribute__((unused)),
                 sqlite3_value **args __attribute__((unused))) {
  PCRE2_UCHAR16 vers[24];
  pcre2_config_16(PCRE2_CONFIG_UNICODE_VERSION, vers);
  sqlite3_result_text16(ctx, vers, -1, SQLITE_TRANSIENT);
}

#endif

#ifdef _WIN32
__declspec(export)
#endif
    int sqlite3_pcrefuncs_init(sqlite3 *db,
                               char **pzErrMsg __attribute__((unused)),
                               const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);

  struct re_funcs {
    const char *name;
    int nargs;
    bool utf8;
    void (*fp)(sqlite3_context *, int, sqlite3_value **);
  } func_table[] = {
#ifdef HAVE_PCRE2_8
      {"pcre_version", 0, 1, re_version8},
      {"pcre_unicode_version", 0, 1, re_unicode8},
      {"regexp", 2, 1, re_regexp8},
      {"pcre_regexp", 2, 1, re_regexp8},
#endif
#ifdef HAVEPCRE2_16
      {"pcre_version", 0, 0, re_version16},
      {"pcre_unicode_version", 0, 0, re_unicode16},
      {"regexp", 2, 0, re_regexp16},
      {"pcre_regexp", 2, 0, re_regexp16},
#endif
      {NULL, 0, 0, NULL}};
  int rc = SQLITE_OK;
  for (int n = 0; func_table[n].name; n += 1) {
    rc = sqlite3_create_function(
        db, func_table[n].name, func_table[n].nargs,
        SQLITE_DETERMINISTIC |
            (func_table[n].utf8 ? SQLITE_UTF8 : SQLITE_UTF16),
        NULL, func_table[n].fp, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }
  return SQLITE_OK;
}
