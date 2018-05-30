/*
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*/

/* String functions that deal with extended grapheme clusters instead
   of strings as a whole. */

#include <assert.h>
#include <stdlib.h>

#include <unicode/uchar.h>
#include <unicode/utf16.h>
#include <unicode/utf8.h>
#include <unicode/utypes.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

typedef enum UGraphemeClusterBreak gcb_cat;
static gcb_cat get_gcb(UChar32 c) {
  return u_getIntPropertyValue(c, UCHAR_GRAPHEME_CLUSTER_BREAK);
}

/* UTF-8 Extended Grapheme Cluster parser */

// returns length of prepend*
static int prepend_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;

  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_PREPEND) {
      return prev_i - start_i;
    }
  }
}

// returns length of Regional_Indicator*
static int ri_sequence_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;

  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_REGIONAL_INDICATOR) {
      return prev_i = start_i;
    }
  }
}

static int l_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_L) {
      return prev_i - start_i;
    }
  }
}

static int v_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_V) {
      return prev_i - start_i;
    }
  }
}

static int t_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_T) {
      return prev_i - start_i;
    }
  }
}

// returns length of Hangul-Syllable
static int hangul_syllable_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;

  // | L+

  i += l_len8(utf8, i, len);

  int prev_i = i;
  U8_NEXT(utf8, i, len, c);
  if (c <= 0) {
    return prev_i - start_i; // | L+
  }
  switch (get_gcb(c)) {
  case U_GCB_V:
  case U_GCB_LV:
    //  L* V+ T*
    // | L* LV V* T*
    i += v_len8(utf8, i, len);
    i += t_len8(utf8, i, len);
    return i - start_i;
  case U_GCB_LVT:
    // | L* LVT T*
    i += t_len8(utf8, i, len);
    return i - start_i;
  case U_GCB_T:
    if (prev_i == start_i) { // | T+
      i += t_len8(utf8, i, len);
      return i - start_i;
    } else {
      return prev_i - start_i; // | L+
    }
  default:
    return prev_i - start_i; // | L+
  }
}

// Returns length of SpacingMark*
static int sm_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_SPACING_MARK) {
      return prev_i - start_i;
    }
  }
}

// Returns length of GraphemeExtend*
static int ge_len8(const char *utf8, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_EXTEND) {
      return prev_i - start_i;
    }
  }
}

// Returns the number of bytes in the leading extended grapheme
// cluster of the given 0-terminated UTF-8 string.
// len can be -1.

int egc_len8(const char *utf8, int len) {
  UChar32 c;
  int i = 0;

  if (!*utf8 || len == 0) {
    return 0;
  }

  // CRLF matches
  if (len != 1 && utf8[0] == '\r' && utf8[1] == '\n') {
    return 2;
  }

  int first_cp = 0;
  U8_NEXT(utf8, first_cp, len, c);
  if (c < 0) {
    return first_cp;
  }

  i = first_cp;
  int prev_i = 0;
  gcb_cat cat = get_gcb(c);
  if (cat == U_GCB_PREPEND) {
    i += prepend_len8(utf8, i, len);
    prev_i = i;
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return first_cp;
    }
    cat = get_gcb(c);
  }

  // (RI-Sequence | Hangul-Syllable | !Control)
  switch (cat) {
  case U_GCB_REGIONAL_INDICATOR:
    i += ri_sequence_len8(utf8, i, len);
    break;
  case U_GCB_L:
  case U_GCB_T:
  case U_GCB_V:
  case U_GCB_LV:
  case U_GCB_LVT:
    i = prev_i;
    i += hangul_syllable_len8(utf8, i, len);
    if (prev_i == i) {
      return first_cp;
    }
    break;
  case U_GCB_CONTROL:
    return first_cp;
  default:
    (void)0;
  }

  // ( Grapheme_Extend | SpacingMark )*
  do {
    prev_i = i;
    U8_NEXT(utf8, i, len, c);
    if (c <= 0) {
      return prev_i;
    }
    cat = get_gcb(c);

    if (cat == U_GCB_EXTEND) {
      i += ge_len8(utf8, i, len);
    } else if (cat == U_GCB_SPACING_MARK) {
      i += sm_len8(utf8, i, len);
    } else {
      return prev_i;
    }
  } while (1);
}

/* UTF-16 Extended Grapheme Cluster Parser */

// returns length of prepend*
static int prepend_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;

  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_PREPEND) {
      return prev_i - start_i;
    }
  }
}

// returns length of Regional_Indicator*
static int ri_sequence_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;

  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_REGIONAL_INDICATOR) {
      return prev_i = start_i;
    }
  }
}

static int l_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_L) {
      return prev_i - start_i;
    }
  }
}

static int v_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_V) {
      return prev_i - start_i;
    }
  }
}

static int t_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_T) {
      return prev_i - start_i;
    }
  }
}

// returns length of Hangul-Syllable
static int hangul_syllable_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;

  // | L+

  i += l_len16(utf16, i, len);

  int prev_i = i;
  U16_NEXT(utf16, i, len, c);
  if (c <= 0) {
    return prev_i - start_i; // | L+
  }
  switch (get_gcb(c)) {
  case U_GCB_V:
  case U_GCB_LV:
    //  L* V+ T*
    // | L* LV V* T*
    i += v_len16(utf16, i, len);
    i += t_len16(utf16, i, len);
    return i - start_i;
  case U_GCB_LVT:
    // | L* LVT T*
    i += t_len16(utf16, i, len);
    return i - start_i;
  case U_GCB_T:
    if (prev_i == start_i) { // | T+
      i += t_len16(utf16, i, len);
      return i - start_i;
    } else {
      return prev_i - start_i; // | L+
    }
  default:
    return prev_i - start_i; // | L+
  }
}

// Returns length of SpacingMark*
static int sm_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_SPACING_MARK) {
      return prev_i - start_i;
    }
  }
}

// Returns length of GraphemeExtend*
static int ge_len16(const UChar *utf16, int i, int len) {
  int start_i = i;
  UChar32 c;
  for (int prev_i = i; 1; prev_i = i) {
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i - start_i;
    }
    if (get_gcb(c) != U_GCB_EXTEND) {
      return prev_i - start_i;
    }
  }
}

// Returns the number of bytes in the leading extended grapheme
// cluster of the given 0-terminated UTF-16 string.
// len can be -1.

int egc_len16(const UChar *utf16, int len) {
  UChar32 c;
  int i = 0;

  if (!*utf16 || len == 0) {
    return 0;
  }

  // CRLF matches
  if (len != 1 && utf16[0] == '\r' && utf16[1] == '\n') {
    return 2;
  }

  int first_cp = 0;
  U16_NEXT(utf16, first_cp, len, c);
  if (c < 0) {
    return first_cp;
  }

  i = first_cp;
  int prev_i = 0;
  gcb_cat cat = get_gcb(c);
  if (cat == U_GCB_PREPEND) {
    i += prepend_len16(utf16, i, len);
    prev_i = i;
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return first_cp;
    }
    cat = get_gcb(c);
  }

  // (RI-Sequence | Hangul-Syllable | !Control)
  switch (cat) {
  case U_GCB_REGIONAL_INDICATOR:
    i += ri_sequence_len16(utf16, i, len);
    break;
  case U_GCB_L:
  case U_GCB_T:
  case U_GCB_V:
  case U_GCB_LV:
  case U_GCB_LVT:
    i = prev_i;
    i += hangul_syllable_len16(utf16, i, len);
    if (prev_i == i) {
      return first_cp;
    }
    break;
  case U_GCB_CONTROL:
    return first_cp;
  default:
    (void)0;
  }

  // ( Grapheme_Extend | SpacingMark )*
  do {
    prev_i = i;
    U16_NEXT(utf16, i, len, c);
    if (c <= 0) {
      return prev_i;
    }
    cat = get_gcb(c);

    if (cat == U_GCB_EXTEND) {
      i += ge_len16(utf16, i, len);
    } else if (cat == U_GCB_SPACING_MARK) {
      i += sm_len16(utf16, i, len);
    } else {
      return prev_i;
    }
  } while (1);
}

/* Provide native UTF-8 and UTF-16 versions of most functions */

static void sf_gclength8(sqlite3_context *c, int nArg __attribute__((unused)),
                         sqlite3_value **apArg) {
  assert(nArg == 1);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const char *utf8 = (const char *)sqlite3_value_text(apArg[0]);
  if (!utf8) {
    return;
  }

  int len = 0;
  while (*utf8) {
    utf8 += egc_len8(utf8, -1);
    len += 1;
  }

  sqlite3_result_int(c, len);
}

static void sf_gclength16(sqlite3_context *c, int nArg __attribute__((unused)),
                          sqlite3_value **apArg) {
  assert(nArg == 1);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  int len = 0;
  while (*utf16) {
    utf16 += egc_len16(utf16, -1);
    len += 1;
  }

  sqlite3_result_int(c, len);
}

static void sf_gcleft8(sqlite3_context *c, int nArg __attribute__((unused)),
                       sqlite3_value **apArg) {
  assert(nArg == 2);
  int endlen = 0;

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const char *utf8 = (const char *)sqlite3_value_text(apArg[0]);
  if (!utf8) {
    return;
  }

  const char *start = utf8;
  int n = sqlite3_value_int(apArg[1]);

  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  } else if (n < 0) {
    int len = 0;

    while (*start) {
      start += egc_len8(start, -1);
      len += 1;
    }
    n = len + n;
    if (n <= 0) {
      sqlite3_result_text(c, "", 0, SQLITE_STATIC);
      return;
    }
    start = utf8;
  }

  while (*utf8 && n--) {
    int len = egc_len8(utf8, -1);
    endlen += len;
    utf8 += len;
  }

  sqlite3_result_text(c, start, endlen, SQLITE_TRANSIENT);
}

static void sf_gcleft16(sqlite3_context *c, int nArg __attribute__((unused)),
                        sqlite3_value **apArg) {
  assert(nArg == 2);
  int endlen = 0;

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  const UChar *start = utf16;
  int n = sqlite3_value_int(apArg[1]);

  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  } else if (n < 0) {
    int len = 0;

    while (*start) {
      start += egc_len16(start, -1);
      len += 1;
    }
    n = len + n;
    if (n <= 0) {
      sqlite3_result_text(c, "", 0, SQLITE_STATIC);
      return;
    }
    start = utf16;
  }

  while (*utf16 && n--) {
    int len = egc_len16(utf16, -1);
    endlen += len;
    utf16 += len;
  }

  sqlite3_result_text16(c, start, endlen * 2, SQLITE_TRANSIENT);
}

static void sf_gcright8(sqlite3_context *c, int nArg __attribute__((unused)),
                        sqlite3_value **apArg) {
  assert(nArg == 2);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const char *utf8 = (const char *)sqlite3_value_text(apArg[0]);
  if (!utf8) {
    return;
  }

  const char *start = utf8;
  int n = sqlite3_value_int(apArg[1]);

  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  }

  int len = 0;
  while (*start) {
    start += egc_len8(start, -1);
    len += 1;
  }

  int skip;
  if (n > 0) {
    skip = len - n;
  } else {
    skip = abs(n);
  }

  if (skip <= 0 || skip > len) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
  }

  while (*utf8 && skip--) {
    utf8 += egc_len8(utf8, -1);
  }

  sqlite3_result_text(c, utf8, -1, SQLITE_TRANSIENT);
}

static void sf_gcright16(sqlite3_context *c, int nArg __attribute__((unused)),
                         sqlite3_value **apArg) {
  assert(nArg == 2);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  const UChar *start = utf16;
  int n = sqlite3_value_int(apArg[1]);

  if (n == 0) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
    return;
  }

  int len = 0;
  while (*start) {
    start += egc_len16(start, -1);
    len += 1;
  }

  int skip;
  if (n > 0) {
    skip = len - n;
  } else {
    skip = abs(n);
  }

  if (skip <= 0 || skip > len) {
    sqlite3_result_text(c, "", 0, SQLITE_STATIC);
  }

  while (*utf16 && skip--) {
    utf16 += egc_len16(utf16, -1);
  }

  sqlite3_result_text16(c, utf16, -1, SQLITE_TRANSIENT);
}

static void sf_gcsubstr8(sqlite3_context *c, int nArg, sqlite3_value **apArg) {
  assert(nArg == 2 || nArg == 3);
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const char *utf8 = (const char *)sqlite3_value_text(apArg[0]);
  if (!utf8) {
    return;
  }

  int start_pos = sqlite3_value_int(apArg[1]);
  if (start_pos <= 0) {
    sqlite3_result_error_code(c, SQLITE_MISUSE);
    return;
  }
  start_pos -= 1;

  int sublen = -1;
  if (nArg == 3) {
    sublen = sqlite3_value_int(apArg[2]);
    if (sublen < 0) {
      sqlite3_result_error_code(c, SQLITE_MISUSE);
      return;
    }
  }

  while (*utf8 && start_pos--) {
    utf8 += = egc_len8(utf8, -1);
  }

  if (sublen == -1) {
    sqlite3_result_text(c, utf8, -1, SQLITE_TRANSIENT);
    return;
  }

  const char *start = utf8;
  int endlen = 0;
  while (*utf8 && sublen--) {
    int len = egc_len8(utf8, -1);
    endlen += len;
    utf8 += len;
  }

  sqlite3_result_text(c, start, endlen, SQLITE_TRANSIENT);
}

static void sf_gcsubstr16(sqlite3_context *c, int nArg, sqlite3_value **apArg) {
  assert(nArg == 2 || nArg == 3);
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  int start_pos = sqlite3_value_int(apArg[1]);
  if (start_pos <= 0) {
    sqlite3_result_error_code(c, SQLITE_MISUSE);
    return;
  }
  start_pos -= 1;

  int sublen = -1;
  if (nArg == 3) {
    sublen = sqlite3_value_int(apArg[2]);
    if (sublen < 0) {
      sqlite3_result_error_code(c, SQLITE_MISUSE);
      return;
    }
  }

  while (*utf16 && start_pos--) {
    utf16 += egc_len16(utf16, -1);
  }

  if (sublen == -1) {
    sqlite3_result_text16(c, utf16, -1, SQLITE_TRANSIENT);
    return;
  }

  const UChar *start = utf16;
  int endlen = 0;
  while (*utf16 && sublen--) {
    int len = egc_len16(utf16, -1);
    endlen += len;
    utf16 += len;
  }

  sqlite3_result_text16(c, start, endlen * 2, SQLITE_TRANSIENT);
}

int sf_egc_init(sqlite3 *db) {
  const struct Scalar {
    const char *zName;  /* Function name */
    int nArg;           /* Number of arguments */
    unsigned short enc; /* Optimal text encoding */
    void *iContext;     /* sqlite3_user_data() context */
    void (*xFunc)(sqlite3_context *, int, sqlite3_value **);
  } scalars[] = {
      {"gclength", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_gclength8},
      {"gclength", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gclength16},
      {"gcleft", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_gcleft8},
      {"gcleft", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcleft16},
      {"gcright", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_gcright8},
      {"gcright", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcright16},
      {"gcsubstr", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr8},
      {"gcsubstr", 3, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr8},
      {"gcsubstr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr16},
      {"gcsubstr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, NULL, sf_gcsubstr16},
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
