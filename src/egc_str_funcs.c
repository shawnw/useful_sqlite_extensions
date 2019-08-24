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

/* String functions that deal with extended grapheme clusters instead
   of strings as a whole. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicode/ubrk.h>
#include <unicode/ustring.h>
#include <unicode/utypes.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

void icuFunctionError(
    sqlite3_context *pCtx, /* SQLite scalar function context */
    const char *zName,     /* Name of ICU function that failed */
    UErrorCode e           /* Error code returned by ICU function */
);

static void closeBreakIterator(void *v) {
  UBreakIterator *bi = v;
  ubrk_close(bi);
}

UBreakIterator *default_charbreak = NULL;

static void sf_gclength16(sqlite3_context *c, int nArg __attribute__((unused)),
                          sqlite3_value **apArg) {
  assert(nArg == 1 || nArg == 2);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }
  if (nArg == 2 && sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }
  UBreakIterator *bi = NULL;
  UErrorCode status = U_ZERO_ERROR;
  if (nArg == 2) {
    bi = sqlite3_get_auxdata(c, 1);
    if (!bi) {
      const char *locale = (const char *)sqlite3_value_text(apArg[1]);
      if (!locale) {
        return;
      }
      bi = ubrk_open(UBRK_CHARACTER, locale, NULL, 0, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(c, "ubrk_open", status);
        return;
      }
      sqlite3_set_auxdata(c, 1, bi, closeBreakIterator);
    }
  } else {
    bi = ubrk_safeClone(default_charbreak, NULL, NULL, &status);
    if (U_FAILURE(status)) {
      icuFunctionError(c, "ubrk_safeClone", status);
      return;
    }
  }

  ubrk_setText(bi, utf16, -1, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(c, "ubrk_setText", status);
    return;
  }

  int len = 0;
  while (ubrk_next(bi) != UBRK_DONE) {
    len += 1;
  }

  if (nArg == 1) {
    ubrk_close(bi);
  }
  sqlite3_result_int(c, len);
}

static void sf_gcleft16(sqlite3_context *c, int nArg __attribute__((unused)),
                        sqlite3_value **apArg) {
  assert(nArg == 2 || nArg == 3);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }
  if (nArg == 3 && sqlite3_value_type(apArg[2]) == SQLITE_NULL) {
    return;
  }

  int n = sqlite3_value_int(apArg[1]);
  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  UErrorCode status = U_ZERO_ERROR;
  UBreakIterator *bi;
  if (nArg == 3) {
    bi = sqlite3_get_auxdata(c, 2);
    if (!bi) {
      const char *locale = (const char *)sqlite3_value_text(apArg[2]);
      if (!locale) {
        return;
      }
      bi = ubrk_open(UBRK_CHARACTER, locale, NULL, 0, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(c, "ubrk_open", status);
        return;
      }
      sqlite3_set_auxdata(c, 2, bi, closeBreakIterator);
    }
  } else {
    bi = ubrk_safeClone(default_charbreak, NULL, NULL, &status);
    if (U_FAILURE(status)) {
      icuFunctionError(c, "ubrk_safeClone", status);
      return;
    }
  }

  ubrk_setText(bi, utf16, -1, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(c, "ubrk_setText", status);
    return;
  }

  int32_t endlen = 0;
  if (n > 0) {
    int32_t off;
    while (n > 0 && (off = ubrk_next(bi)) != UBRK_DONE) {
      endlen = off;
      n -= 1;
    }
  } else if (n < 0) {
    int32_t off;
    ubrk_last(bi);
    while (n < 0 && (off = ubrk_previous(bi)) != UBRK_DONE) {
      endlen = off;
      n += 1;
    }
  }
  sqlite3_result_text16(c, utf16, endlen * 2, SQLITE_TRANSIENT);
  if (nArg == 2) {
    ubrk_close(bi);
  }
}

static void sf_gcright16(sqlite3_context *c, int nArg __attribute__((unused)),
                         sqlite3_value **apArg) {

  assert(nArg == 2 || nArg == 3);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  int n = sqlite3_value_int(apArg[1]);
  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  UErrorCode status = U_ZERO_ERROR;
  UBreakIterator *bi;
  if (nArg == 3) {
    bi = sqlite3_get_auxdata(c, 2);
    if (!bi) {
      const char *locale = (const char *)sqlite3_value_text(apArg[2]);
      if (!locale) {
        return;
      }
      bi = ubrk_open(UBRK_CHARACTER, locale, NULL, 0, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(c, "ubrk_open", status);
        return;
      }
      sqlite3_set_auxdata(c, 2, bi, closeBreakIterator);
    }
  } else {
    bi = ubrk_safeClone(default_charbreak, NULL, NULL, &status);
    if (U_FAILURE(status)) {
      icuFunctionError(c, "ubrk_safeClone", status);
      return;
    }
  }

  ubrk_setText(bi, utf16, -1, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(c, "ubrk_setText", status);
    return;
  }

  int32_t off = 0, nextoff = 0;
  if (n > 0) {
    ubrk_last(bi);
    while (n > 0 && (nextoff = ubrk_previous(bi)) != UBRK_DONE) {
      n -= 1;
      off = nextoff;
    }
  } else {
    while (n < 0 && (nextoff = ubrk_next(bi)) != UBRK_DONE) {
      off = nextoff;
      n += 1;
    }
  }
  sqlite3_result_text16(c, utf16 + off, -1, SQLITE_TRANSIENT);
  if (nArg == 2) {
    ubrk_close(bi);
  }
}

static void sf_gcsubstr16(sqlite3_context *c, int nArg, sqlite3_value **apArg) {
  assert(nArg >= 2 && nArg <= 4);
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }
  if (nArg >= 3 && sqlite3_value_type(apArg[2]) == SQLITE_NULL) {
    return;
  }
  if (nArg == 4 && sqlite3_value_type(apArg[3]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  int start_pos = sqlite3_value_int(apArg[1]);
  if (start_pos <= 0) {
    sqlite3_result_error_code(c, SQLITE_RANGE);
    return;
  }
  start_pos -= 1;

  int sublen = -1;
  if (nArg == 3) {
    sublen = sqlite3_value_int(apArg[2]);
    if (sublen < -1) {
      sqlite3_result_error_code(c, SQLITE_RANGE);
      return;
    }
  }

  UErrorCode status = U_ZERO_ERROR;
  UBreakIterator *bi;
  if (nArg == 4) {
    bi = sqlite3_get_auxdata(c, 3);
    if (!bi) {
      const char *locale = (const char *)sqlite3_value_text(apArg[3]);
      if (!locale) {
        return;
      }
      bi = ubrk_open(UBRK_CHARACTER, locale, NULL, 0, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(c, "ubrk_open", status);
        return;
      }
      sqlite3_set_auxdata(c, 3, bi, closeBreakIterator);
    }
  } else {
    bi = ubrk_safeClone(default_charbreak, NULL, NULL, &status);
    if (U_FAILURE(status)) {
      icuFunctionError(c, "ubrk_safeClone", status);
      return;
    }
  }

  ubrk_setText(bi, utf16, -1, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(c, "ubrk_setText", status);
    return;
  }

  int32_t off = 0, nextoff = 0;
  while (start_pos > 0 && (nextoff = ubrk_next(bi)) != UBRK_DONE) {
    start_pos -= 1;
    off = nextoff;
  }

  if (sublen == -1) {
    sqlite3_result_text16(c, utf16 + off, -1, SQLITE_TRANSIENT);
    if (nArg != 4) {
      ubrk_close(bi);
    }
    return;
  }

  int32_t endoff = 0;
  while (sublen > 0 && (nextoff = ubrk_next(bi)) != UBRK_DONE) {
    sublen -= 1;
    endoff = nextoff;
  }

  sqlite3_result_text16(c, utf16 + off, (endoff - off) * 2, SQLITE_TRANSIENT);
  if (nArg != 4) {
    ubrk_close(bi);
  }
}

/* Eponymous-only virtual tables to break strings */

struct break_vtab {
  sqlite3_vtab base;
  UBreakIteratorType type;
};

struct break_cursor {
  sqlite3_vtab_cursor base;
  sqlite3_int64 rowid;
  char *locale;
  UChar *utf16;
  UBreakIterator *bi;
  int cps_seen;
  int32_t start_off;
  int32_t end_off;
};

static int breakConnect(sqlite3 *db, void *pAux,
                        int argc __attribute__((unused)),
                        const char *const *argv __attribute__((unused)),
                        sqlite3_vtab **ppVtab,
                        char **pzErr __attribute__((unused))) {
  struct break_vtab *bv;
  int rc;

#define BREAK_COLUMN_VALUE 0
#define BREAK_COLUMN_START 1
#define BREAK_COLUMN_LEN 2
#define BREAK_COLUMN_TXT 3
#define BREAK_COLUMN_LOCALE 4

  rc = sqlite3_declare_vtab(db, "CREATE TABLE x(value TEXT, start INTEGER, "
                                "len INTEGER, txt hidden, locale hidden)");
  if (rc != SQLITE_OK) {
    return rc;
  }
  bv = sqlite3_malloc(sizeof *bv);
  if (!bv) {
    return SQLITE_NOMEM;
  }
  *ppVtab = &bv->base;
  memset(bv, 0, sizeof *bv);
  bv->type = (UBreakIteratorType)pAux;
  return SQLITE_OK;
}

static int breakDisconnect(sqlite3_vtab *pVtab) {
  sqlite3_free(pVtab);
  return SQLITE_OK;
}

static int breakOpen(sqlite3_vtab *p __attribute__((unused)),
                     sqlite3_vtab_cursor **ppCursor) {
  struct break_cursor *bc = sqlite3_malloc(sizeof *bc);
  if (!bc) {
    return SQLITE_NOMEM;
  }
  memset(bc, 0, sizeof *bc);
  *ppCursor = &bc->base;
  bc->cps_seen = -1;
  return SQLITE_OK;
}

static int breakClose(sqlite3_vtab_cursor *cur) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  if (bc->bi) {
    ubrk_close(bc->bi);
  }
  sqlite3_free(bc->utf16);
  sqlite3_free(bc->locale);
  sqlite3_free(bc);
  return SQLITE_OK;
}

static int breakNext(sqlite3_vtab_cursor *cur) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  if (bc->cps_seen >= 0) {
    bc->cps_seen +=
        u_countChar32(bc->utf16 + bc->start_off, bc->end_off - bc->start_off);
  }
  bc->start_off = bc->end_off;
  bc->end_off = ubrk_next(bc->bi);
  bc->rowid += 1;
  return SQLITE_OK;
}

static int breakColumn(sqlite3_vtab_cursor *cur, sqlite3_context *c, int i) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  switch (i) {
  default:
  case BREAK_COLUMN_VALUE:
    if (bc->utf16) {
      sqlite3_result_text16(c, bc->utf16 + bc->start_off,
                            (bc->end_off - bc->start_off) * 2, SQLITE_STATIC);
    }
    break;
  case BREAK_COLUMN_START:
    if (bc->utf16) {
      if (bc->cps_seen < 0) {
        bc->cps_seen = u_countChar32(bc->utf16, bc->start_off);
      }
      sqlite3_result_int(c, bc->cps_seen + 1);
    }
    break;
  case BREAK_COLUMN_LEN:
    if (bc->utf16) {
      sqlite3_result_int(c, u_countChar32(bc->utf16 + bc->start_off,
                                          bc->end_off - bc->start_off));
    }
    break;
  case BREAK_COLUMN_TXT:
    if (bc->utf16) {
      sqlite3_result_text16(c, bc->utf16, -1, SQLITE_STATIC);
    }
    break;
  case BREAK_COLUMN_LOCALE:
    if (bc->locale) {
      sqlite3_result_text(c, bc->locale, -1, SQLITE_STATIC);
    }
    break;
  }
  return SQLITE_OK;
}

static int breakRowid(sqlite3_vtab_cursor *cur, sqlite3_int64 *pRowid) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  *pRowid = bc->rowid;
  return SQLITE_OK;
}

static int breakEof(sqlite3_vtab_cursor *cur) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  return !bc->utf16 || bc->end_off == UBRK_DONE;
}

static int breakFilter(sqlite3_vtab_cursor *cur,
                       int idxNum __attribute__((unused)),
                       const char *idxStr __attribute__((unused)), int argc,
                       sqlite3_value **argv) {
  struct break_cursor *bc = (struct break_cursor *)cur;
  struct break_vtab *bv = (struct break_vtab *)bc->base.pVtab;

  assert(argc == 1 || argc == 2);

  if (sqlite3_value_type(argv[0]) == SQLITE_NULL) {
    return SQLITE_OK;
  }

  if (argc == 2) {
    if (sqlite3_value_type(argv[1]) != SQLITE_NULL) {
      bc->locale = sqlite3_mprintf("%s", sqlite3_value_text(argv[1]));
      if (!bc->locale) {
        return SQLITE_NOMEM;
      }
    }
  }

  const void *u16 = sqlite3_value_text16(argv[0]);
  if (!u16) {
    return SQLITE_OK;
  }
  int32_t len = sqlite3_value_bytes16(argv[0]);
  bc->utf16 = sqlite3_malloc(len + 2);
  memcpy(bc->utf16, u16, len);
  bc->utf16[len / 2] = 0;

  UErrorCode status = U_ZERO_ERROR;
  bc->bi = ubrk_open(bv->type, bc->locale, bc->utf16, -1, &status);
  if (U_FAILURE(status)) {
    sqlite3_free(bc->utf16);
    sqlite3_free(bc->locale);
    sqlite3_free(cur->pVtab->zErrMsg);
    cur->pVtab->zErrMsg =
        sqlite3_mprintf("ICU error: ubrk_open(): %s", u_errorName(status));
    return SQLITE_ERROR;
  }

  return breakNext(cur);
}

static int breakBestIndex(sqlite3_vtab *tab, sqlite3_index_info *pIdxInfo) {
  int aIdx[2] = {-1, -1};
  int unusableMask = 0;
  int idxMask = 0;
  _Bool start_requested = 0, len_requested = 0;
  const struct sqlite3_index_constraint *pConstraint = pIdxInfo->aConstraint;
  for (int i = 0; i < pIdxInfo->nConstraint; i++, pConstraint++) {
    if (pConstraint->iColumn < BREAK_COLUMN_TXT) {
      if (pConstraint->usable && pConstraint->iColumn == BREAK_COLUMN_START) {
        start_requested = 1;
      } else

          if (pConstraint->usable && pConstraint->iColumn == BREAK_COLUMN_LEN) {
        len_requested = 1;
      }
      continue;
    }
    int iCol = pConstraint->iColumn - BREAK_COLUMN_TXT;
    int iMask = 1 << iCol;
    if (pConstraint->usable == 0) {
      unusableMask |= iMask;
    } else if (pConstraint->op == SQLITE_INDEX_CONSTRAINT_EQ) {
      aIdx[iCol] = i;
      idxMask |= iMask;
    }
  }
  if ((unusableMask & !idxMask) != 0) {
    return SQLITE_CONSTRAINT;
  }
  if (aIdx[0] >= 0) {
    int i = aIdx[0];
    pIdxInfo->aConstraintUsage[i].argvIndex = 1;
    pIdxInfo->aConstraintUsage[i].omit = 1;
  }
  if (aIdx[1] >= 0) {
    int i = aIdx[1];
    pIdxInfo->aConstraintUsage[i].argvIndex = 2;
    pIdxInfo->aConstraintUsage[i].omit = 1;
    pIdxInfo->idxNum = 2;
  } else {
    pIdxInfo->idxNum = 1;
  }

#undef MAX
#define MAX(a, b) (a) > (b) ? (a) : (b)
  int cost = 0;
  struct break_vtab *bv = (struct break_vtab *)tab;
  if (bv->type == UBRK_CHARACTER) {
    cost = 500;
  } else {
    /* Word and sentence tokenizing is more expensive as there are
     * more code points to scan. */
    cost = 1200;
  }
  /* Counting the code points to the starting index is only done on
   * demand; expensive once for the first count if not done from the
   * very beginning. Amortize the costs. */
  if (start_requested) {
    if (bv->type == UBRK_CHARACTER) {
      cost += 100;
    } else if (bv->type == UBRK_WORD) {
      cost += 200;
    } else {
      cost += 400;
    }
  }
  /* Counting the code points in the token is more expensive for words
   * and sentences than characters. */
  if (len_requested) {
    if (bv->type == UBRK_CHARACTER) {
      cost = MAX(cost, 550);
    } else if (bv->type == UBRK_WORD) {
      cost = MAX(cost, 1500);
    } else {
      cost = MAX(cost, 4000);
    }
  }
  pIdxInfo->estimatedCost = cost;
  return SQLITE_OK;
}

static sqlite3_module breakModule = {
    1,               // iVersion
    0,               // xCreate
    breakConnect,    // xConnect
    breakBestIndex,  // xBestIndex
    breakDisconnect, // xDisconnect
    0,               // xDestroy
    breakOpen,       // xOpen
    breakClose,      // xClose
    breakFilter,     // xFilter
    breakNext,       // xNext
    breakEof,        // xEof
    breakColumn,     // xColumn
    breakRowid,      // xRowid
    0,               // xUpdate
    0,               // xBegin
    0,               // xSync
    0,               // xCommit
    0,               // xRollback
    0,               // xFindFunction
    0,               // xRename
    0,               // xSavepoint
    0,               // xRelease
    0,               // xRollbackTo
#if SQLITE_VERSION_NUMBER >= 3026000
    0, // xShadowName
#endif
};

int sf_egc_init(sqlite3 *db, char **pzErrMsg) {
  const struct Scalar {
    const char *zName;  /* Function name */
    int nArg;           /* Number of arguments */
    unsigned short enc; /* Optimal text encoding */
    void *iContext;     /* sqlite3_user_data() context */
    void (*xFunc)(sqlite3_context *, int, sqlite3_value **);
  } scalars[] = {
      {"gclength", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gclength16},
      {"gclength", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gclength16},
      {"gcleft", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcleft16},
      {"gcleft", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcleft16},
      {"gcright", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcright16},
      {"gcright", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcright16},
      {"gcsubstr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr16},
      {"gcsubstr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr16},
      {"gcsubstr", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr16},
      {NULL, -1, 0, NULL, NULL}};
  const struct Break {
    const char *name;
    UBreakIteratorType type;
  } breaks[] = {{"graphemes", UBRK_CHARACTER},
                {"words", UBRK_WORD},
                {"sentences", UBRK_SENTENCE},
                {"lines", UBRK_LINE},
                {NULL, UBRK_COUNT}};
  int rc = SQLITE_OK;
  UErrorCode status = U_ZERO_ERROR;

  if (!default_charbreak) {
    default_charbreak = ubrk_open(UBRK_CHARACTER, NULL, NULL, 0, &status);
    if (U_FAILURE(status)) {
      if (pzErrMsg) {
        *pzErrMsg =
            sqlite3_mprintf("ICU error: ubrk_open(): %s", u_errorName(status));
      }
      return SQLITE_ERROR;
    }
  }

  for (int i = 0; rc == SQLITE_OK && scalars[i].zName; i += 1) {
    const struct Scalar *p = &scalars[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg, p->enc, p->iContext,
                                 p->xFunc, 0, 0);
  }

  for (int i = 0; rc == SQLITE_OK && breaks[i].name; i += 1) {
    rc = sqlite3_create_module(db, breaks[i].name, &breakModule,
                               (void *)breaks[i].type);
  }

  return rc;
}
