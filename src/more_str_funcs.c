/*
Copyright 2018-2019 Shawn Wagner

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

/* Additional string functions that don't involve unicode character
   properties or the like. */

#define _XOPEN_SOURCE

#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

static char *do_append(sqlite3_context *p, char *zOut, sqlite3_uint64 *nOut,
                       const char *zApp, int nApp) {
  sqlite3_int64 newLen = *nOut + nApp;

  if (nApp == 0) {
    return zOut;
  }

  char *zNew = sqlite3_realloc64(zOut, newLen);
  if (!zNew) {
    sqlite3_free(zOut);
    sqlite3_result_error_nomem(p);
    return NULL;
  }

  memcpy(zNew + *nOut, zApp, nApp);
  *nOut = newLen;
  return zNew;
}

static void sf_concat(sqlite3_context *p, int nArg, sqlite3_value **apArg) {
  char *zOut = NULL;
  sqlite3_uint64 nOut = 0;
  _Bool empty = 0;
  // MySQL concat() returns NULL if given any NULL arguments, Postgres
  // just ignores NULLS.
  _Bool mysql_style = sqlite3_user_data(p);

  for (int n = 0; n < nArg; n += 1) {
    if (sqlite3_value_type(apArg[n]) == SQLITE_NULL) {
      if (mysql_style) {
        sqlite3_free(zOut);
        return;
      }
      continue;
    }

    const char *zArg = (const char *)sqlite3_value_text(apArg[n]);
    int arglen = sqlite3_value_bytes(apArg[n]);

    if (arglen == 0) {
      empty = 1;
      continue;
    }

    zOut = do_append(p, zOut, &nOut, zArg, arglen);
    if (!zOut) {
      return;
    }
  }

  if (zOut) {
    sqlite3_result_text64(p, zOut, nOut, sqlite3_free, SQLITE_UTF8);
  } else if (empty) {
    sqlite3_result_text(p, "", 0, SQLITE_STATIC);
  }
}

static void sf_concat_ws(sqlite3_context *p, int nArg, sqlite3_value **apArg) {
  if (nArg <= 1) {
    return;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const char *zSep = (const char *)sqlite3_value_text(apArg[0]);
  int nSep = sqlite3_value_bytes(apArg[0]);

  char *zOut = NULL;
  sqlite3_uint64 nOut = 0;

  for (int n = 1; n < nArg; n += 1) {
    if (sqlite3_value_type(apArg[n]) == SQLITE_NULL) {
      continue;
    }

    const char *zArg = (const char *)sqlite3_value_text(apArg[n]);
    int arglen = sqlite3_value_bytes(apArg[n]);

    if (zOut) {
      zOut = do_append(p, zOut, &nOut, zSep, nSep);
      if (!zOut) {
        return;
      }
      zOut = do_append(p, zOut, &nOut, zArg, arglen);
      if (!zOut) {
        return;
      }
    } else {
      if (arglen > 0) {
        zOut = sqlite3_malloc(arglen);
        if (!zOut) {
          sqlite3_result_error_nomem(p);
          return;
        }
        memcpy(zOut, zArg, arglen);
        nOut = arglen;
      } else {
        zOut = sqlite3_malloc(1);
        if (!zOut) {
          sqlite3_result_error_nomem(p);
          return;
        }
        *zOut = 0;
      }
    }
  }

  if (zOut) {
    sqlite3_result_text64(p, zOut, nOut, sqlite3_free, SQLITE_UTF8);
  }
}

static void sf_repeat8(sqlite3_context *p, int nArg __attribute__((unused)),
                       sqlite3_value **apArg) {
  assert(nArg == 2);
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  const unsigned char *t = sqlite3_value_text(apArg[0]);
  int tlen = sqlite3_value_bytes(apArg[0]);
  int reps = sqlite3_value_int(apArg[1]);

  if (reps <= 0) {
    return;
  }

  sqlite3_uint64 olen = (sqlite3_uint64)reps * tlen;
  unsigned char *output = sqlite3_malloc64(olen);
  if (!output) {
    sqlite3_result_error_nomem(p);
    return;
  }

  size_t off = 0;
  while (reps--) {
    memcpy(output + off, t, tlen);
    off += tlen;
  }
  sqlite3_result_text64(p, (const char *)output, olen, sqlite3_free,
                        SQLITE_UTF8);
}

static void sf_strptime(sqlite3_context *ctx,
                        int nArg __attribute__((__unused__)),
                        sqlite3_value **apArg) {
  assert(nArg == 2);

#ifdef HAVE_STRPTIME
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  const char *fmt = (const char *)sqlite3_value_text(apArg[0]);
  const char *s = (const char *)sqlite3_value_text(apArg[1]);

  if (!fmt || !s) {
    return;
  }

  struct tm t;
  memset(&t, 0, sizeof t);
  char *end = strptime(s, fmt, &t);
  if (!end || *end) {
    return;
  }

  time_t secs = mktime(&t);
  if (secs != (time_t)-1) {
    sqlite3_result_int64(ctx, (sqlite3_int64)secs);
  }
#endif
}

int sf_more_init(sqlite3 *db) {
  const struct Scalar {
    const char *zName;  /* Function name */
    int nArg;           /* Number of arguments */
    unsigned short enc; /* Optimal text encoding */
    void *iContext;     /* sqlite3_user_data() context */
    void (*xFunc)(sqlite3_context *, int, sqlite3_value **);
  } scalars[] = {
      {"concat", -1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_concat},
      {"mysql_concat", -1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, (void *)1,
       sf_concat},
      {"concat_ws", -1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_concat_ws},
      {"repeat", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_repeat8},
      {"strptime", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_strptime},
  };
  int rc = SQLITE_OK;

  for (int i = 0;
       rc == SQLITE_OK && i < (int)(sizeof(scalars) / sizeof(scalars[0]));
       i++) {
    const struct Scalar *p = &scalars[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg, p->enc, p->iContext,
                                 p->xFunc, 0, 0);
  }

  return rc;
}
