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

/* String functions that mostly require knowledge of Unicode features
   of the codepoints in them. */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unicode/ucnv.h>
#include <unicode/ucol.h>
#include <unicode/unorm2.h>
#include <unicode/uregex.h>
#include <unicode/ustring.h>
#include <unicode/utf16.h>
#include <unicode/uversion.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

typedef void (*version_func)(UVersionInfo);

static void icuVersionFunc(sqlite3_context *p, int nArg __attribute__((unused)),
                           sqlite3_value **apArg __attribute__((unused))) {
  UVersionInfo vers;
  char versstr[U_MAX_VERSION_STRING_LENGTH];
  version_func vf = (version_func *)sqlite3_user_data(p);

  vf(vers);

  u_versionToString(vers, versstr);
  sqlite3_result_text(p, versstr, -1, SQLITE_TRANSIENT);
}

static uint32_t parse_re_options(const unsigned char *zOptions, int *group) {
  uint32_t options = 0;
  if (zOptions) {
    while (*zOptions) {
      unsigned char c = *zOptions++;
      switch (c) {
      case 'i':
        options |= UREGEX_CASE_INSENSITIVE;
        break;
      case 'c':
        options &= ~UREGEX_CASE_INSENSITIVE;
        break;
      case 'm':
        options |= UREGEX_MULTILINE;
        break;
      case 'n':
        options |= UREGEX_DOTALL;
        break;
      case 'u':
        options |= UREGEX_UNIX_LINES;
        break;
      case 'w':
        options |= UREGEX_UWORD;
        break;
      case 'x':
        options |= UREGEX_COMMENTS;
        break;
      case 'l':
        options |= UREGEX_LITERAL;
        break;
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
        if (group) {
          *group = c - '0';
        }
        break;
      default:
        /* Ignore unknown flags */
        (void)0;
      }
    }
  }
  return options;
}

/* Taken straight from icu.c with very minor changes:
 *
 * regexp() takes a 3rd argument with options.
 * icu_load_collation() creates both UTF-8 and UTF-16 versions.
 * TODO: Use ICU utf-8 functions and macros?
 */

/*
** This function is called when an ICU function called from within
** the implementation of an SQL scalar function returns an error.
**
** The scalar function context passed as the first argument is
** loaded with an error message based on the following two args.
*/
static void
icuFunctionError(sqlite3_context *pCtx, /* SQLite scalar function context */
                 const char *zName,     /* Name of ICU function that failed */
                 UErrorCode e /* Error code returned by ICU function */
) {
  char zBuf[128];
  sqlite3_snprintf(128, zBuf, "ICU error: %s(): %s", zName, u_errorName(e));
  zBuf[127] = '\0';
  sqlite3_result_error(pCtx, zBuf, -1);
}

/*
** Maximum length (in bytes) of the pattern in a LIKE or GLOB
** operator.
*/
#ifndef SQLITE_MAX_LIKE_PATTERN_LENGTH
#define SQLITE_MAX_LIKE_PATTERN_LENGTH 50000
#endif

/*
** Version of sqlite3_free() that is always a function, never a macro.
*/
static void xFree(void *p) { sqlite3_free(p); }

/*
** This lookup table is used to help decode the first byte of
** a multi-byte UTF8 character. It is copied here from SQLite source
** code file utf8.c.
*/
static const unsigned char icuUtf8Trans1[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00,
};

#define SQLITE_ICU_READ_UTF8(zIn, c)                                           \
  c = *(zIn++);                                                                \
  if (c >= 0xc0) {                                                             \
    c = icuUtf8Trans1[c - 0xc0];                                               \
    while ((*zIn & 0xc0) == 0x80) {                                            \
      c = (c << 6) + (0x3f & *(zIn++));                                        \
    }                                                                          \
  }

#define SQLITE_ICU_SKIP_UTF8(zIn)                                              \
  assert(*zIn);                                                                \
  if (*(zIn++) >= 0xc0) {                                                      \
    while ((*zIn & 0xc0) == 0x80) {                                            \
      zIn++;                                                                   \
    }                                                                          \
  }

/*
** Compare two UTF-8 strings for equality where the first string is
** a "LIKE" expression. Return true (1) if they are the same and
** false (0) if they are different.
*/
static int
icuLikeCompare(const uint8_t *zPattern, /* LIKE pattern */
               const uint8_t *zString, /* The UTF-8 string to compare against */
               const UChar32 uEsc      /* The escape character */
) {
  static const uint32_t MATCH_ONE = (uint32_t)'_';
  static const uint32_t MATCH_ALL = (uint32_t)'%';

  int prevEscape = 0; /* True if the previous character was uEsc */

  while (1) {

    /* Read (and consume) the next character from the input pattern. */
    uint32_t uPattern;
    SQLITE_ICU_READ_UTF8(zPattern, uPattern);
    if (uPattern == 0)
      break;

    /* There are now 4 possibilities:
    **
    **     1. uPattern is an unescaped match-all character "%",
    **     2. uPattern is an unescaped match-one character "_",
    **     3. uPattern is an unescaped escape character, or
    **     4. uPattern is to be handled as an ordinary character
    */
    if (!prevEscape && uPattern == MATCH_ALL) {
      /* Case 1. */
      uint8_t c;

      /* Skip any MATCH_ALL or MATCH_ONE characters that follow a
      ** MATCH_ALL. For each MATCH_ONE, skip one character in the
      ** test string.
      */
      while ((c = *zPattern) == MATCH_ALL || c == MATCH_ONE) {
        if (c == MATCH_ONE) {
          if (*zString == 0)
            return 0;
          SQLITE_ICU_SKIP_UTF8(zString);
        }
        zPattern++;
      }

      if (*zPattern == 0)
        return 1;

      while (*zString) {
        if (icuLikeCompare(zPattern, zString, uEsc)) {
          return 1;
        }
        SQLITE_ICU_SKIP_UTF8(zString);
      }
      return 0;

    } else if (!prevEscape && uPattern == MATCH_ONE) {
      /* Case 2. */
      if (*zString == 0)
        return 0;
      SQLITE_ICU_SKIP_UTF8(zString);

    } else if (!prevEscape && uPattern == (uint32_t)uEsc) {
      /* Case 3. */
      prevEscape = 1;

    } else {
      /* Case 4. */
      uint32_t uString;
      SQLITE_ICU_READ_UTF8(zString, uString);
      uString = (uint32_t)u_foldCase((UChar32)uString, U_FOLD_CASE_DEFAULT);
      uPattern = (uint32_t)u_foldCase((UChar32)uPattern, U_FOLD_CASE_DEFAULT);
      if (uString != uPattern) {
        return 0;
      }
      prevEscape = 0;
    }
  }

  return *zString == 0;
}

/*
** Implementation of the like() SQL function.  This function implements
** the build-in LIKE operator.  The first argument to the function is the
** pattern and the second argument is the string.  So, the SQL statements:
**
**       A LIKE B
**
** is implemented as like(B, A). If there is an escape character E,
**
**       A LIKE B ESCAPE E
**
** is mapped to like(B, A, E).
*/
static void icuLikeFunc(sqlite3_context *context, int argc,
                        sqlite3_value **argv) {
  const unsigned char *zA = sqlite3_value_text(argv[0]);
  const unsigned char *zB = sqlite3_value_text(argv[1]);
  UChar32 uEsc = 0;

  /* Limit the length of the LIKE or GLOB pattern to avoid problems
  ** of deep recursion and N*N behavior in patternCompare().
  */
  if (sqlite3_value_bytes(argv[0]) > SQLITE_MAX_LIKE_PATTERN_LENGTH) {
    sqlite3_result_error(context, "LIKE or GLOB pattern too complex", -1);
    return;
  }

  if (argc == 3) {
    /* The escape character string must consist of a single UTF-8 character.
    ** Otherwise, return an error.
    */
    int nE = sqlite3_value_bytes(argv[2]);
    const unsigned char *zE = sqlite3_value_text(argv[2]);
    int i = 0;
    if (zE == 0)
      return;
    U8_NEXT(zE, i, nE, uEsc);
    if (i != nE) {
      sqlite3_result_error(context,
                           "ESCAPE expression must be a single character", -1);
      return;
    }
  }

  if (zA && zB) {
    sqlite3_result_int(context, icuLikeCompare(zA, zB, uEsc));
  }
}

/*
** Function to delete compiled regexp objects. Registered as
** a destructor function with sqlite3_set_auxdata().
*/
static void icuRegexpDelete(void *p) {
  URegularExpression *pExpr = (URegularExpression *)p;
  uregex_close(pExpr);
}

/*
** Implementation of SQLite REGEXP operator. This scalar function takes
** two arguments. The first is a regular expression pattern to compile
** the second is a string to match against that pattern. If either
** argument is an SQL NULL, then NULL Is returned. Otherwise, the result
** is 1 if the string matches the pattern, or 0 otherwise.
**
** SQLite maps the regexp() function to the regexp() operator such
** that the following two are equivalent:
**
**     zString REGEXP zPattern
**     regexp(zPattern, zString)
**
** Uses the following ICU regexp APIs:
**
**     uregex_open()
**     uregex_matches()
**     uregex_close()
*/
static void icuRegexpFunc(sqlite3_context *p, int nArg, sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;
  URegularExpression *pExpr;
  UBool res;
  const UChar *zString = sqlite3_value_text16(apArg[1]);
  uint32_t options = 0;

  (void)nArg; /* Unused parameter */

  /* If the left hand side of the regexp operator is NULL,
  ** then the result is also NULL.
  */
  if (!zString) {
    return;
  }

  if (nArg == 3) {
    options = parse_re_options(sqlite3_value_text(apArg[2]), NULL);
  }

  pExpr = sqlite3_get_auxdata(p, 0);
  if (!pExpr) {
    const UChar *zPattern = sqlite3_value_text16(apArg[0]);
    if (!zPattern) {
      return;
    }
    pExpr = uregex_open(zPattern, -1, options, 0, &status);

    if (U_SUCCESS(status)) {
      sqlite3_set_auxdata(p, 0, pExpr, icuRegexpDelete);
    } else {
      assert(!pExpr);
      icuFunctionError(p, "uregex_open", status);
      return;
    }
  }

  /* Configure the text that the regular expression operates on. */
  uregex_setText(pExpr, zString, -1, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_setText", status);
    return;
  }

  /* Attempt the match */
  res = uregex_matches(pExpr, 0, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_matches", status);
    return;
  }

  /* Set the text that the regular expression operates on to a NULL
  ** pointer. This is not really necessary, but it is tidier than
  ** leaving the regular expression object configured with an invalid
  ** pointer after this function returns.
  */
  uregex_setText(pExpr, 0, 0, &status);

  /* Return 1 or 0. */
  sqlite3_result_int(p, res ? 1 : 0);
}

/*
** Implementations of scalar functions for case mapping - upper() and
** lower(). Function upper() converts its input to upper-case (ABC).
** Function lower() converts to lower-case (abc).
**
** ICU provides two types of case mapping, "general" case mapping and
** "language specific". Refer to ICU documentation for the differences
** between the two.
**
** To utilise "general" case mapping, the upper() or lower() scalar
** functions are invoked with one argument:
**
**     upper('ABC') -> 'abc'
**     lower('abc') -> 'ABC'
**
** To access ICU "language specific" case mapping, upper() or lower()
** should be invoked with two arguments. The second argument is the name
** of the locale to use. Passing an empty string ("") or SQL NULL value
** as the second argument is the same as invoking the 1 argument version
** of upper() or lower().
**
**     lower('I', 'en_us') -> 'i'
**     lower('I', 'tr_tr') -> '\u131' (small dotless i)
**
** http://www.icu-project.org/userguide/posix.html#case_mappings
*/
static void icuCaseFunc16(sqlite3_context *p, int nArg, sqlite3_value **apArg) {
  const UChar *zInput; /* Pointer to input string */
  UChar *zOutput = 0;  /* Pointer to output buffer */
  int nInput;          /* Size of utf-16 input string in bytes */
  int nOut;            /* Size of output buffer in bytes */
  int cnt;
  int bToUpper; /* True for toupper(), false for tolower() */
  UErrorCode status;
  const char *zLocale = 0;

  assert(nArg == 1 || nArg == 2);
  bToUpper = (sqlite3_user_data(p) != 0);
  if (nArg == 2) {
    zLocale = (const char *)sqlite3_value_text(apArg[1]);
  }

  zInput = sqlite3_value_text16(apArg[0]);
  if (!zInput) {
    return;
  }
  nOut = nInput = sqlite3_value_bytes16(apArg[0]);
  if (nOut == 0) {
    sqlite3_result_text16(p, "", 0, SQLITE_STATIC);
    return;
  }

  for (cnt = 0; cnt < 2; cnt++) {
    UChar *zNew = sqlite3_realloc(zOutput, nOut);
    if (zNew == 0) {
      sqlite3_free(zOutput);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOutput = zNew;
    status = U_ZERO_ERROR;
    if (bToUpper) {
      nOut = 2 * u_strToUpper(zOutput, nOut / 2, zInput, nInput / 2, zLocale,
                              &status);
    } else {
      nOut = 2 * u_strToLower(zOutput, nOut / 2, zInput, nInput / 2, zLocale,
                              &status);
    }

    if (U_SUCCESS(status)) {
      sqlite3_result_text16(p, zOutput, nOut, xFree);
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, bToUpper ? "u_strToUpper" : "u_strToLower", status);
    }
    return;
  }
  assert(0); /* Unreachable */
}

/*
** Collation sequence destructor function. The pCtx argument points to
** a UCollator structure previously allocated using ucol_open().
*/
static void icuCollationDel(void *pCtx) {
  UCollator *p = (UCollator *)pCtx;
  ucol_close(p);
}

/*
** Collation sequence comparison function using UTF-16. The pCtx
* argument points to a UCollator structure previously allocated
* using ucol_open().
*/
static int icuCollationColl16(void *pCtx, int nLeft, const void *zLeft,
                              int nRight, const void *zRight) {
  UCollationResult res;
  UCollator *p = (UCollator *)pCtx;
  res = ucol_strcoll(p, (const UChar *)zLeft, nLeft / 2, (const UChar *)zRight,
                     nRight / 2);
  switch (res) {
  case UCOL_LESS:
    return -1;
  case UCOL_GREATER:
    return +1;
  case UCOL_EQUAL:
    return 0;
  }
  assert(!"Unexpected return value from ucol_strcoll()");
  return 0;
}

/*
** Collation sequence comparison function using UTF-8. The pCtx
* argument points to a UCollator structure previously allocated using
* ucol_open().
*/
static int icuCollationColl8(void *pCtx, int nLeft, const void *zLeft,
                             int nRight, const void *zRight) {
  UErrorCode status = U_ZERO_ERROR;
  UCollationResult res;
  UCollator *p = (UCollator *)pCtx;
  res = ucol_strcollUTF8(p, (const char *)zLeft, nLeft, (const char *)zRight,
                         nRight, &status);
  assert(U_SUCCESS(status));
  switch (res) {
  case UCOL_LESS:
    return -1;
  case UCOL_GREATER:
    return +1;
  case UCOL_EQUAL:
    return 0;
  }
  assert(!"Unexpected return value from ucol_strcollUTF8()");
  return 0;
}

/*
** Implementation of the scalar function icu_load_collation().
**
** This scalar function is used to add ICU collation based collation
** types to an SQLite database connection. It is intended to be called
** as follows:
**
**     SELECT icu_load_collation(<locale>, <collation-name>);
**
** Where <locale> is a string containing an ICU locale identifier (i.e.
** "en_AU", "tr_TR" etc.) and <collation-name> is the name of the
** collation sequence to create.
*/
static void icuLoadCollation(sqlite3_context *p,
                             int nArg __attribute__((unused)),
                             sqlite3_value **apArg) {
  sqlite3 *db = (sqlite3 *)sqlite3_user_data(p);
  UErrorCode status = U_ZERO_ERROR;
  const char *zLocale;   /* Locale identifier - (eg. "jp_JP") */
  const char *zName;     /* SQL Collation sequence name (eg. "japanese") */
  UCollator *pUCollator; /* ICU library collation object */
  int rc;                /* Return code from sqlite3_create_collation_x() */

  assert(nArg == 2);
  zLocale = (const char *)sqlite3_value_text(apArg[0]);
  zName = (const char *)sqlite3_value_text(apArg[1]);

  if (!zLocale || !zName) {
    return;
  }

  pUCollator = ucol_open(zLocale, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "ucol_open", status);
    return;
  }
  assert(pUCollator);

  UCollator *pUCollator2 = ucol_safeClone(pUCollator, NULL, NULL, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "ucol_safeClone", status);
    ucol_close(pUCollator);
    return;
  }
  assert(pUCollator2);

  rc = sqlite3_create_collation_v2(db, zName, SQLITE_UTF16, (void *)pUCollator,
                                   icuCollationColl16, icuCollationDel);
  if (rc != SQLITE_OK) {
    sqlite3_result_error(p, "Error registering collation function", -1);
    ucol_close(pUCollator2);
    return;
  }

  rc = sqlite3_create_collation_v2(db, zName, SQLITE_UTF8, (void *)pUCollator2,
                                   icuCollationColl8, icuCollationDel);
  if (rc != SQLITE_OK) {
    ucol_close(pUCollator2);
    sqlite3_result_error(p, "Error registering collation function", -1);
  }
}

/* Back to original stuff */

/* Based on icuCaseFunc16 */
static void icuTitleFunc16(sqlite3_context *p, int nArg,
                           sqlite3_value **apArg) {
  const UChar *zInput; /* Pointer to input string */
  UChar *zOutput = 0;  /* Pointer to output buffer */
  int nInput;          /* Size of utf-16 input string in bytes */
  sqlite3_uint64 nOut; /* Size of output buffer in bytes */
  UErrorCode status;
  const char *zLocale = 0;

  assert(nArg == 1 || nArg == 2);
  if (nArg == 2) {
    zLocale = (const char *)sqlite3_value_text(apArg[1]);
  }

  zInput = sqlite3_value_text16(apArg[0]);
  if (!zInput) {
    return;
  }
  nOut = nInput = sqlite3_value_bytes16(apArg[0]);
  if (nInput == 0) {
    sqlite3_result_text16(p, "", 0, SQLITE_STATIC);
    return;
  }

  for (int cnt = 0; cnt < 2; cnt++) {
    UChar *zNew = sqlite3_realloc64(zOutput, nOut);
    if (zNew == 0) {
      sqlite3_free(zOutput);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOutput = zNew;
    status = U_ZERO_ERROR;
    nOut = (sqlite3_uint64)2 * u_strToTitle(zOutput, nOut / 2, zInput,
                                            nInput / 2, NULL, zLocale, &status);

    if (U_SUCCESS(status)) {
      sqlite3_result_text64(p, (char *)zOutput, nOut, sqlite3_free,
                            SQLITE_UTF16);
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "u_strToTitle", status);
      sqlite3_free(zOutput);
    }
    return;
  }
  assert(0); /* Unreachable */
}

/* Basec on icuCaseFunc16 */
static void icuCaseFoldFunc16(sqlite3_context *p,
                              int nArg __attribute__((unused)),
                              sqlite3_value **apArg) {
  const UChar *zInput; /* Pointer to input string */
  UChar *zOutput = 0;  /* Pointer to output buffer */
  int nInput;          /* Size of utf-16 input string in bytes */
  sqlite3_uint64 nOut; /* Size of output buffer in bytes */
  UErrorCode status;

  assert(nArg == 1);

  zInput = sqlite3_value_text16(apArg[0]);
  if (!zInput) {
    return;
  }
  nOut = nInput = sqlite3_value_bytes16(apArg[0]);
  if (nInput == 0) {
    sqlite3_result_text16(p, "", 0, SQLITE_STATIC);
    return;
  }

  for (int cnt = 0; cnt < 2; cnt++) {
    UChar *zNew = sqlite3_realloc64(zOutput, nOut);
    if (zNew == 0) {
      sqlite3_free(zOutput);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOutput = zNew;
    status = U_ZERO_ERROR;
    nOut =
        (sqlite3_uint64)2 * u_strFoldCase(zOutput, nOut / 2, zInput, nInput / 2,
                                          U_FOLD_CASE_DEFAULT, &status);

    if (U_SUCCESS(status)) {
      sqlite3_result_text64(p, (char *)zOutput, nOut, sqlite3_free,
                            SQLITE_UTF16);
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "u_strFoldCase", status);
      sqlite3_free(zOutput);
    }
    return;
  }
  assert(0); /* Unreachable */
}

typedef const UNormalizer2 *(*norm_func)(UErrorCode *);
static struct normalization_forms {
  const char *name;
  norm_func f;
  const char *fname;
} normalizers[] = {{"NFC", unorm2_getNFCInstance, "unorm2_getNFCInstance"},
                   {"NFD", unorm2_getNFDInstance, "unorm2_getNFDInstance"},
                   {"NFKC", unorm2_getNFKCInstance, "unorm2_getNFKCInstance"},
                   {"NFKD", unorm2_getNFKDInstance, "unorm2_getNFKDInstance"},
                   {"NFKCCaseFold", unorm2_getNFKCCasefoldInstance,
                    "unorm2_getNFKCCasefoldInstance"},
                   {NULL, NULL, NULL}};

static const UNormalizer2 *icu_getNormForm(sqlite3_context *ctx,
                                           const char *form) {
  UErrorCode status = U_ZERO_ERROR;
  if (form) {
    for (int n = 0; normalizers[n].name; n += 1) {
      if (sqlite3_stricmp(normalizers[n].name, form) == 0) {
        const UNormalizer2 *norm = normalizers[n].f(&status);
        if (U_FAILURE(status)) {
          icuFunctionError(ctx, normalizers[n].fname, status);
          return NULL;
        }
        return norm;
      }
    }
  }
  sqlite3_result_error(ctx, "Invalid normalization form.", -1);
  return NULL;
}

static UChar *icuNormalizeUChar(sqlite3_context *p, const UNormalizer2 *norm,
                                const UChar *zInput, int nInput,
                                sqlite3_uint64 *nOutput) {
  UErrorCode status = U_ZERO_ERROR;
  UChar *zOut = NULL;
  sqlite3_uint64 nOut = nInput;

  if (nInput == 0) {
    zOut = sqlite3_malloc(2);
    if (!zOut) {
      sqlite3_result_error_nomem(p);
      return NULL;
    }
    *zOut = 0;
    if (nOutput) {
      *nOutput = 0;
    }
    return zOut;
  }

  if (unorm2_quickCheck(norm, zInput, nInput / 2, &status) == UNORM_YES &&
      U_SUCCESS(status)) {
    // fast path for an already appropriately normalized string
    zOut = sqlite3_malloc(nInput);
    if (!zOut) {
      sqlite3_result_error_nomem(p);
      return NULL;
    }
    memcpy(zOut, zInput, nInput);
    if (nOutput) {
      *nOutput = nInput;
    }
    return zOut;
  } else {
    for (int cnt = 0; cnt < 2; cnt++) {
      UChar *zNew = sqlite3_realloc64(zOut, nOut);
      if (zNew == 0) {
        sqlite3_free(zOut);
        sqlite3_result_error_nomem(p);
        return NULL;
      }
      zOut = zNew;
      status = U_ZERO_ERROR;
      nOut = (sqlite3_uint64)2 * unorm2_normalize(norm, zInput, nInput / 2,
                                                  zOut, nOut / 2, &status);
      if (U_SUCCESS(status)) {
        if (nOutput) {
          *nOutput = nOut;
        }
        return zOut;
      } else if (status == U_BUFFER_OVERFLOW_ERROR) {
        assert(cnt == 0);
        continue;
      } else {
        icuFunctionError(p, "unorm2_normalize", status);
        sqlite3_free(zOut);
        return NULL;
      }
    }
  }
  assert(0);
  return NULL;
}

// Normalize a string
static void icuNormFunc16(sqlite3_context *p, int nArg __attribute__((unused)),
                          sqlite3_value **apArg) {
  const UChar *zInput; /* Pointer to input string */
  UChar *zOutput = 0;  /* Pointer to output buffer */
  int nInput;          /* Size of utf-16 input string in bytes */
  sqlite3_uint64 nOut; /* Size of output buffer in bytes */

  assert(nArg == 2);

  const char *form = (const char *)sqlite3_value_text(apArg[1]);

  const UNormalizer2 *norm = icu_getNormForm(p, form);
  if (!norm) {
    return;
  }

  zInput = sqlite3_value_text16(apArg[0]);
  if (!zInput) {
    return;
  }
  nInput = sqlite3_value_bytes16(apArg[0]);
  if (nInput == 0) {
    sqlite3_result_text(p, "", 0, SQLITE_STATIC);
    return;
  }

  zOutput = icuNormalizeUChar(p, norm, zInput, nInput, &nOut);
  if (zOutput) {
    sqlite3_result_text64(p, (char *)zOutput, nOut, sqlite3_free, SQLITE_UTF16);
  }
}

// Append two normalized strings
static UChar *icuAppendNormUChars(sqlite3_context *p, const UNormalizer2 *norm,
                                  UChar *zOutput, sqlite3_uint64 *nOutput,
                                  const UChar *zApp, int nApp) {
  UErrorCode status = U_ZERO_ERROR;
  sqlite3_uint64 nOut = *nOutput;
  sqlite3_uint64 nNewLen = nOut + nApp;

  if (nApp == 0) {
    return zOutput;
  }

  for (int cnt = 0; cnt < 2; cnt++) {
    UChar *zNew = sqlite3_realloc64(zOutput, nNewLen);
    if (zNew == 0) {
      sqlite3_free(zOutput);
      sqlite3_result_error_nomem(p);
      return NULL;
    }
    zOutput = zNew;
    status = U_ZERO_ERROR;
    nNewLen =
        (sqlite3_uint64)2 * unorm2_append(norm, zOutput, nOut / 2, nNewLen / 2,
                                          zApp, nApp / 2, &status);
    if (U_SUCCESS(status)) {
      *nOutput = nNewLen;
      return zOutput;
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "unorm2_append", status);
      return NULL;
    }
  }
  assert(0);
  return NULL;
}

// Append an unnormal string to a normalized one
static UChar *icuAppendUnNormUChars(sqlite3_context *p,
                                    const UNormalizer2 *norm, UChar *zOutput,
                                    sqlite3_uint64 *nOutput, const UChar *zApp,
                                    int nApp) {
  UErrorCode status = U_ZERO_ERROR;
  sqlite3_uint64 nOut = *nOutput;
  sqlite3_uint64 nNewLen = nOut + nApp;

  for (int cnt = 0; cnt < 2; cnt++) {
    UChar *zNew = sqlite3_realloc64(zOutput, nNewLen);
    if (zNew == 0) {
      sqlite3_free(zOutput);
      sqlite3_result_error_nomem(p);
      return NULL;
    }
    zOutput = zNew;
    status = U_ZERO_ERROR;
    nNewLen = (sqlite3_uint64)2 * unorm2_normalizeSecondAndAppend(
                                      norm, zOutput, nOut / 2, nNewLen / 2,
                                      zApp, nApp / 2, &status);
    if (U_SUCCESS(status)) {
      *nOutput = nNewLen;
      return zOutput;
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "unorm2_normalizeSecondAndAppend", status);
      return NULL;
    }
  }
  assert(0);
  return NULL;
}

static void icuNormConcatFunc16(sqlite3_context *p, int nArg,
                                sqlite3_value **apArg) {
  const UNormalizer2 *norm = sqlite3_user_data(p);
  UChar *zOutput = NULL;
  sqlite3_uint64 nOut = 0;
  _Bool empty = 0;
  UErrorCode status;

  for (int n = 0; n < nArg; n += 1) {
    if (sqlite3_value_type(apArg[n]) == SQLITE_NULL) {
      continue;
    }
    int nInput;
    const UChar *zInput = sqlite3_value_text16(apArg[n]);
    if (!zInput) {
      continue;
    }
    nInput = sqlite3_value_bytes16(apArg[n]);
    if (nInput == 0) {
      empty = 1;
      continue;
    }
    if (zOutput) {
      if (unorm2_quickCheck(norm, zInput, nInput / 2, &status) == UNORM_YES &&
          U_SUCCESS(status)) {
        zOutput = icuAppendNormUChars(p, norm, zOutput, &nOut, zInput, nInput);
        if (!zOutput) {
          return;
        }
      } else {
        // String to append isn't normalized
        zOutput =
            icuAppendUnNormUChars(p, norm, zOutput, &nOut, zInput, nInput);
        if (!zOutput) {
          return;
        }
      }
    } else {
      // First non-null argument
      zOutput = icuNormalizeUChar(p, norm, zInput, nInput, &nOut);
      if (!zOutput) {
        return;
      }
    }
  }

  if (zOutput) {
    sqlite3_result_text64(p, (char *)zOutput, nOut, sqlite3_free, SQLITE_UTF16);
  } else if (empty) {
    sqlite3_result_text(p, "", 0, SQLITE_STATIC);
  }
}

static void icuRepeatFunc16(sqlite3_context *p,
                            int nArg __attribute__((unused)),
                            sqlite3_value **apArg) {
  assert(nArg == 3);

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  const char *form = (const char *)sqlite3_value_text(apArg[2]);
  const UNormalizer2 *norm = icu_getNormForm(p, form);
  if (!norm) {
    return;
  }

  int reps = sqlite3_value_int(apArg[1]);
  if (reps <= 0) {
    return;
  }

  const UChar *utf16 = sqlite3_value_text16(apArg[0]);
  if (!utf16) {
    return;
  }

  int len = sqlite3_value_bytes16(apArg[0]);

  sqlite3_uint64 nlen;
  UChar *normed = icuNormalizeUChar(p, norm, utf16, len, &nlen);
  if (!normed) {
    return;
  }

  UChar *zOut = sqlite3_malloc64(nlen);
  sqlite3_uint64 nOut = nlen;
  if (!zOut) {
    sqlite3_free(normed);
    sqlite3_result_error_nomem(p);
  }
  memcpy(zOut, normed, nlen);
  reps -= 1;

  while (reps--) {
    UChar *zNew = icuAppendNormUChars(p, norm, zOut, &nOut, normed, nlen);
    if (!zNew) {
      sqlite3_free(normed);
      return;
    }
    zOut = zNew;
  }
  sqlite3_free(normed);
  sqlite3_result_text64(p, (char *)zOut, nOut, sqlite3_free, SQLITE_UTF16);
}

static void icuNormConcatWSFunc16(sqlite3_context *p, int nArg,
                                  sqlite3_value **apArg) {
  const UNormalizer2 *norm = sqlite3_user_data(p);
  UChar *zOutput = NULL;
  sqlite3_uint64 nOut = 0;
  UErrorCode status;
  UChar *zSep = NULL;
  sqlite3_uint64 nSep;

  if (nArg <= 1) {
    return;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  {
    const UChar *sep = sqlite3_value_text16(apArg[0]);
    int sepbytes = sqlite3_value_bytes16(apArg[0]);
    zSep = icuNormalizeUChar(p, norm, sep, sepbytes, &nSep);
    if (!zSep) {
      return;
    }
  }

  for (int n = 1; n < nArg; n += 1) {
    if (sqlite3_value_type(apArg[n]) == SQLITE_NULL) {
      continue;
    }

    int nInput;
    const UChar *zInput = sqlite3_value_text16(apArg[n]);
    nInput = sqlite3_value_bytes16(apArg[n]);
    if (zOutput) {
      zOutput = icuAppendNormUChars(p, norm, zOutput, &nOut, zSep, nSep);
      if (!zOutput) {
        return;
      }
      if (unorm2_quickCheck(norm, zInput, nInput / 2, &status) == UNORM_YES &&
          U_SUCCESS(status)) {
        // fast path for appending an already appropriately normalized string
        zOutput = icuAppendNormUChars(p, norm, zOutput, &nOut, zInput, nInput);
        if (!zOutput) {
          return;
        }
      } else {
        // String to append isn't normalized
        zOutput =
            icuAppendUnNormUChars(p, norm, zOutput, &nOut, zInput, nInput);
        if (!zOutput) {
          return;
        }
      }
    } else {
      // First non-null argument
      zOutput = icuNormalizeUChar(p, norm, zInput, nInput, &nOut);
      if (!zOutput) {
        return;
      }
    }
  }

  if (zOutput) {
    sqlite3_result_text64(p, (char *)zOutput, nOut, sqlite3_free, SQLITE_UTF16);
  }
}

static UConverter *master_scsu = NULL;
static UConverter *master_bocu1 = NULL;

static void icuCompressFunc(sqlite3_context *p,
                            int nArg __attribute__((unused)),
                            sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;

  UConverter **master = sqlite3_user_data(p);
  UConverter *pConv = ucnv_safeClone(*master, NULL, NULL, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "ucnv_safeClone", status);
    return;
  }

  const UChar *zIn = sqlite3_value_text16(apArg[0]);
  int nIn = sqlite3_value_bytes16(apArg[0]) / 2;
  if (!zIn) {
    return;
  }

  char *zOut = NULL;
  int nOut = nIn;
  for (int cnt = 0; cnt < 2; cnt += 1) {
    char *zNew = sqlite3_realloc(zOut, nOut);
    if (!zNew) {
      ucnv_close(pConv);
      sqlite3_free(zOut);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOut = zNew;
    status = U_ZERO_ERROR;
    nOut = ucnv_fromUChars(pConv, zOut, nOut, zIn, nIn, &status);
    if (U_SUCCESS(status)) {
      sqlite3_result_blob(p, zOut, nOut, sqlite3_free);
      ucnv_close(pConv);
      return;
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "ucnv_fromUChars", status);
      ucnv_close(pConv);
      sqlite3_free(zOut);
      return;
    }
  }
  assert(0);
}

static void icuDecompressFunc(sqlite3_context *p,
                              int nArg __attribute__((unused)),
                              sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;

  UConverter **master = sqlite3_user_data(p);
  UConverter *pConv = ucnv_safeClone(*master, NULL, NULL, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "ucnv_safeClone", status);
    return;
  }

  const char *zIn = sqlite3_value_blob(apArg[0]);
  int nIn = sqlite3_value_bytes(apArg[0]);
  if (!zIn) {
    return;
  }

  UChar *zOut = NULL;
  sqlite3_uint64 nOut = (sqlite3_uint64)nIn * 4;
  for (int cnt = 0; cnt < 2; cnt += 1) {
    UChar *zNew = sqlite3_realloc64(zOut, nOut);
    if (!zNew) {
      ucnv_close(pConv);
      sqlite3_free(zOut);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOut = zNew;
    status = U_ZERO_ERROR;
    nOut = (sqlite3_uint64)2 *
           ucnv_toUChars(pConv, zOut, nOut / 2, zIn, nIn, &status);
    if (U_SUCCESS(status)) {
      sqlite3_result_text64(p, (char *)zOut, nOut, sqlite3_free, SQLITE_UTF16);
      ucnv_close(pConv);
      return;
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "ucnv_fromUChars", status);
      ucnv_close(pConv);
      sqlite3_free(zOut);
      return;
    }
  }
  assert(0);
}

/*
 * Implementation of MySQL style REGEXP_LIKE() function, using ICU
 * regexs.
 */
static void icuRegexpLikeFunc(sqlite3_context *p, int nArg,
                              sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;
  URegularExpression *pExpr;
  const UChar *zString = sqlite3_value_text16(apArg[0]);
  uint32_t options = 0;

  /* If the left hand side of the regexp operator is NULL,
  ** then the result is also NULL.
  */
  if (!zString) {
    return;
  }

  /* Set options */
  if (nArg == 3) {
    options = parse_re_options(sqlite3_value_text(apArg[2]), NULL);
  }

  pExpr = sqlite3_get_auxdata(p, 0);
  if (!pExpr) {
    const UChar *zPattern = sqlite3_value_text16(apArg[1]);
    if (!zPattern) {
      return;
    }

    int nPattern = sqlite3_value_bytes16(apArg[1]) / 2;
    pExpr = uregex_open(zPattern, nPattern, options, 0, &status);

    if (U_SUCCESS(status)) {
      sqlite3_set_auxdata(p, 0, pExpr, icuRegexpDelete);
    } else {
      assert(!pExpr);
      icuFunctionError(p, "uregex_open", status);
      return;
    }
  }

  /* Configure the text that the regular expression operates on. */
  int nString = sqlite3_value_bytes16(apArg[0]) / 2;
  uregex_setText(pExpr, zString, nString, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_setText", status);
    return;
  }

  /* Attempt the match */
  UBool res = uregex_find(pExpr, 0, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_find", status);
    return;
  }

  uregex_reset(pExpr, 0, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_reset", status);
    return;
  }

  /* Return 1 or 0. */
  sqlite3_result_int(p, res ? 1 : 0);
}

/*
 * Implementation of MySQL style REGEXP_INSTR() function, using ICU
 * regexs.
 */
static void icuRegexpInstrFunc(sqlite3_context *p, int nArg,
                               sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;
  URegularExpression *pExpr;
  const UChar *zString = sqlite3_value_text16(apArg[0]);
  int startpos = 0;
  int occurence = 1;
  _Bool return_end = 0;
  uint32_t options = 0;
  int group = 0;

  /* If the left hand side of the regexp operator is NULL,
  ** then the result is also NULL.
  */
  if (!zString) {
    return;
  }

  /* Set options */
  if (nArg == 6) {
    options = parse_re_options(sqlite3_value_text(apArg[5]), &group);
  }

  pExpr = sqlite3_get_auxdata(p, 0);
  if (!pExpr) {
    const UChar *zPattern = sqlite3_value_text16(apArg[1]);
    if (!zPattern) {
      return;
    }

    int nPattern = sqlite3_value_bytes16(apArg[1]) / 2;
    pExpr = uregex_open(zPattern, nPattern, options, 0, &status);

    if (U_SUCCESS(status)) {
      sqlite3_set_auxdata(p, 0, pExpr, icuRegexpDelete);
    } else {
      assert(!pExpr);
      icuFunctionError(p, "uregex_open", status);
      return;
    }
  }

  /* Configure the text that the regular expression operates on. */
  int nString = sqlite3_value_bytes16(apArg[0]) / 2;
  uregex_setText(pExpr, zString, nString, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_setText", status);
    return;
  }

  if (nArg >= 3) {
    int startcp = sqlite3_value_int(apArg[2]) - 1;
    if (startcp < 0) {
      sqlite3_result_error(p, "position out of range", -1);
      return;
    }
    U16_FWD_N(zString, startpos, nString, startcp);
  }

  if (nArg >= 4) {
    occurence = sqlite3_value_int(apArg[3]);
    if (occurence < 1) {
      sqlite3_result_error(p, "occurence out of range", -1);
      return;
    }
  }

  if (nArg >= 5) {
    return_end = sqlite3_value_int(apArg[4]);
  }

  /* Attempt the match */
  UBool res = uregex_find(pExpr, startpos, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_find", status);
    return;
  }
  sqlite3_result_int(p, 0);
  if (!res) {
    return;
  }
  int tries = 1;
  do {
    if (tries++ == occurence) {
      int ret;
      if (return_end) {
        ret = uregex_end(pExpr, group, &status);
        if (!U_SUCCESS(status)) {
          icuFunctionError(p, "uregex_end", status);
          return;
        }
      } else {
        ret = uregex_start(pExpr, group, &status);
        if (!U_SUCCESS(status)) {
          icuFunctionError(p, "uregex_start", status);
          return;
        }
      }
      sqlite3_result_int(p, u_countChar32(zString, ret) + 1);
      break;
    }
  } while (uregex_findNext(pExpr, &status) && U_SUCCESS(status));
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_findNext", status);
    return;
  }

  uregex_reset(pExpr, 0, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_reset", status);
    return;
  }
}

/*
 * Implementation of MySQL style REGEXP_REPLACE() function, using ICU
 * regexs.
 */
static void icuRegexpRepFunc(sqlite3_context *p, int nArg,
                             sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;
  URegularExpression *pExpr;
  const UChar *zString = sqlite3_value_text16(apArg[0]);
  const UChar *zRep = sqlite3_value_text16(apArg[2]);
  int startpos = 0;
  int occurence = 0;
  uint32_t options = 0;

  /* If the left hand side of the regexp operator is NULL,
  ** then the result is also NULL.
  */
  if (!zString || !zRep) {
    return;
  }

  /* Set options */
  if (nArg == 6) {
    options = parse_re_options(sqlite3_value_text(apArg[5]), NULL);
  }

  pExpr = sqlite3_get_auxdata(p, 0);
  if (!pExpr) {
    const UChar *zPattern = sqlite3_value_text16(apArg[1]);
    if (!zPattern) {
      return;
    }

    int nPattern = sqlite3_value_bytes16(apArg[1]) / 2;
    pExpr = uregex_open(zPattern, nPattern, options, 0, &status);

    if (U_SUCCESS(status)) {
      sqlite3_set_auxdata(p, 0, pExpr, icuRegexpDelete);
    } else {
      assert(!pExpr);
      icuFunctionError(p, "uregex_open", status);
      return;
    }
  }

  /* Configure the text that the regular expression operates on. */
  int nString = sqlite3_value_bytes16(apArg[0]) / 2;
  uregex_setText(pExpr, zString, nString, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_setText", status);
    return;
  }

  if (nArg >= 4) {
    int startcp = sqlite3_value_int(apArg[3]) - 1;
    if (startcp != 0) {
      sqlite3_result_error(p, "pos must be 1", -1);
      return;
    }
    U16_FWD_N(zString, startpos, nString, startcp);
  }

  if (nArg >= 5) {
    occurence = sqlite3_value_int(apArg[4]);
    if (occurence < 0 || occurence > 1) {
      sqlite3_result_error(p, "occurence out of range", -1);
      return;
    }
  }

  int nRep = sqlite3_value_bytes16(apArg[2]) / 2;

  sqlite3_uint64 nOut = (sqlite3_uint64)nString * 4;
  UChar *zOut = NULL;

  for (int cnt = 0; cnt < 2; cnt += 1) {
    UChar *zNew = sqlite3_realloc64(zOut, nOut);
    if (!zNew) {
      sqlite3_free(zOut);
      sqlite3_result_error_nomem(p);
      return;
    }
    zOut = zNew;
    status = U_ZERO_ERROR;
    if (occurence == 0) {
      nOut = (sqlite3_uint64)2 *
             uregex_replaceAll(pExpr, zRep, nRep, zOut, nOut / 2, &status);
    } else {
      // occurence == 1
      nOut = (sqlite3_uint64)2 *
             uregex_replaceFirst(pExpr, zRep, nRep, zOut, nOut / 2, &status);
    }
    if (U_SUCCESS(status)) {
      sqlite3_result_text64(p, (char *)zOut, nOut, sqlite3_free, SQLITE_UTF16);
      break;
    } else if (status == U_BUFFER_OVERFLOW_ERROR) {
      assert(cnt == 0);
      continue;
    } else {
      icuFunctionError(p, "uregex_replaceAll", status);
      sqlite3_free(zOut);
      return;
    }
  }
  uregex_reset(pExpr, 0, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_reset", status);
    return;
  }
}

/*
 * Implementation of MySQL style REGEXP_SUBSTR() function, using ICU
 * regexs.
 */
static void icuRegexpSubstrFunc(sqlite3_context *p, int nArg,
                                sqlite3_value **apArg) {
  UErrorCode status = U_ZERO_ERROR;
  URegularExpression *pExpr;
  const UChar *zString = sqlite3_value_text16(apArg[0]);
  int startpos = 0;
  int occurence = 1;
  uint32_t options = 0;
  int group = 0;

  /* If the left hand side of the regexp operator is NULL,
  ** then the result is also NULL.
  */
  if (!zString) {
    return;
  }

  /* Set options */
  if (nArg == 5) {
    options = parse_re_options(sqlite3_value_text(apArg[4]), &group);
  }

  pExpr = sqlite3_get_auxdata(p, 0);
  if (!pExpr) {
    const UChar *zPattern = sqlite3_value_text16(apArg[1]);
    if (!zPattern) {
      return;
    }

    int nPattern = sqlite3_value_bytes16(apArg[1]) / 2;
    pExpr = uregex_open(zPattern, nPattern, options, 0, &status);

    if (U_SUCCESS(status)) {
      sqlite3_set_auxdata(p, 0, pExpr, icuRegexpDelete);
    } else {
      assert(!pExpr);
      icuFunctionError(p, "uregex_open", status);
      return;
    }
  }

  /* Configure the text that the regular expression operates on. */
  int nString = sqlite3_value_bytes16(apArg[0]) / 2;
  uregex_setText(pExpr, zString, nString, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_setText", status);
    return;
  }

  if (nArg >= 3) {
    int startcp = sqlite3_value_int(apArg[2]) - 1;
    if (startcp < 0) {
      sqlite3_result_error(p, "position out of range", -1);
      return;
    }
    U16_FWD_N(zString, startpos, nString, startcp);
  }

  if (nArg >= 4) {
    occurence = sqlite3_value_int(apArg[3]);
    if (occurence < 1) {
      sqlite3_result_error(p, "occurence out of range", -1);
      return;
    }
  }

  /* Attempt the match */
  UBool res = uregex_find(pExpr, startpos, &status);
  if (!U_SUCCESS(status)) {
    icuFunctionError(p, "uregex_find", status);
    return;
  }
  sqlite3_result_null(p);
  if (!res) {
    return;
  }
  int tries = 1;
  do {
    if (tries++ == occurence) {
      int start = uregex_start(pExpr, group, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(p, "uregex_start", status);
        return;
      }
      int end = uregex_end(pExpr, group, &status);
      if (U_FAILURE(status)) {
        icuFunctionError(p, "uregex_end", status);
        return;
      }
      sqlite3_result_text16(p, zString + start, (end - start) * 2,
                            SQLITE_TRANSIENT);
      break;
    }
  } while (uregex_findNext(pExpr, &status) && U_SUCCESS(status));
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_findNext", status);
    return;
  }

  uregex_reset(pExpr, 0, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "uregex_reset", status);
    return;
  }
}

#if 0
// Doesn't do as good a job as the manual version
static void icuStripAccents2Func(sqlite3_context *p, int nArg __attribute__((unused)), sqlite3_value **apArg)
{
  UErrorCode status = U_ZERO_ERROR;
  U_STRING_DECL(trans_id, "Any-Latin; Latin-ASCII", 23);
  U_STRING_INIT(trans_id, "Any-Latin; Latin-ASCII", 23); 
  UTransliterator *trans = utrans_openU(trans_id, -1, UTRANS_FORWARD, NULL,
                                        0, NULL, &status);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "utrans_openU", status);
    return;
  }

  const UChar *zIn = sqlite3_value_text16(apArg[0]);
  int nIn = sqlite3_value_bytes16(apArg[0]);
  
  sqlite3_uint64 nOut = (sqlite3_int64)nIn * 8;
  UChar *zOut = sqlite3_malloc64(nOut);
  if (!zOut) {
    utrans_close(trans);
    sqlite3_result_error_nomem(p);
    return;
  }
  memcpy(zOut, zIn, nIn);
  nIn /= 2;
  int limit = nIn;
  utrans_transUChars(trans, zOut, &nIn, nOut / 2, 0, &limit, &status);
  utrans_close(trans);
  if (U_FAILURE(status)) {
    icuFunctionError(p, "utrans_transUChars", status);
    sqlite3_free(zOut);
    return;
  }

  sqlite3_result_text64(p, (char *)zOut, nIn * 2, sqlite3_free, SQLITE_UTF16);
}
#endif

static int icuCodepointCmp(void *arg __attribute__((unused)), int lena,
                           const void *va, int lenb, const void *vb) {
  const UChar *a = va, *b = vb;
  return u_strCompare(a, lena / 2, b, lenb / 2, 1);
}

static int icuNoCaseCmp(void *arg __attribute__((unused)), int lena,
                        const void *va, int lenb, const void *vb) {
  const UChar *a = va, *b = vb;
  UErrorCode status = U_ZERO_ERROR;

  int cmp = u_strCaseCompare(a, lena / 2, b, lenb / 2,
                             U_COMPARE_CODE_POINT_ORDER, &status);
  assert(U_SUCCESS(status));
  return cmp;
}

static int icuEquivCmp(void *arg, int lena, const void *va, int lenb,
                       const void *vb) {
  const UChar *a = va, *b = vb;
  UErrorCode status = U_ZERO_ERROR;
  int options = U_COMPARE_CODE_POINT_ORDER;

  if (arg != NULL) {
    options |= U_COMPARE_IGNORE_CASE;
  }

  int cmp = unorm_compare(a, lena / 2, b, lenb / 2, options, &status);
  assert(U_SUCCESS(status));
  return cmp;
}

static void char_name(sqlite3_context *ctx, UChar32 c) {
  char *name;
  UErrorCode err = U_ZERO_ERROR;

  name = sqlite3_malloc(128);
  int len = u_charName(c, U_UNICODE_CHAR_NAME, name, 128, &err);
  if (U_SUCCESS(err)) {
    sqlite3_result_text(ctx, name, len, sqlite3_free);
  } else {
    icuFunctionError(ctx, "u_charName", err);
  }
}

void icuCharName8(sqlite3_context *p, int argc __attribute__((unused)),
                  sqlite3_value **argv) {
  assert(argc == 1);
  UChar32 c;

  const unsigned char *utf8 = sqlite3_value_text(argv[0]);

  U8_GET(utf8, 0, 0, -1, c);

  if (c < 0) {
    sqlite3_result_error(p, "invalid utf-8 code point", -1);
  } else {
    char_name(p, c);
  }
}

void icuCharName16(sqlite3_context *p, int argc __attribute__((unused)),
                   sqlite3_value **argv) {
  assert(argc == 1);
  UChar32 c;

  const UChar *utf16 = sqlite3_value_text16(argv[0]);

  U16_GET(utf16, 0, 0, -1, c);

  if (c < 0) {
    sqlite3_result_error(p, "invalid utf-16 code point", -1);
  } else {
    char_name(p, c);
  }
}

void icuStripAccentsFunc(sqlite3_context *context, int argc,
                         sqlite3_value **argv);

/*
** Register the ICU extension functions with database db.
*/
static int sqlite3IcuExtInitFuncs(sqlite3 *db) {
  const struct IcuScalar {
    const char *zName; /* Function name */
    int nArg;          /* Number of arguments */
    int enc;           /* Optimal text encoding */
    void *iContext;    /* sqlite3_user_data() context */
    void (*xFunc)(sqlite3_context *, int, sqlite3_value **);
  } scalars[] = {
    // Base ICU functions
    {"icu_load_collation", 2, SQLITE_UTF8, db, icuLoadCollation},
    {"regexp", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuRegexpFunc},
    {"regexp", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuRegexpFunc},
    {"icu_regexp", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuRegexpFunc},
    {"icu_regexp", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuRegexpFunc},
    {"lower", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuCaseFunc16},
    {"lower", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuCaseFunc16},
    {"upper", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, (void *)1, icuCaseFunc16},
    {"upper", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, (void *)1, icuCaseFunc16},
    {"lower", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, 0, icuCaseFunc16},
    {"upper", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, (void *)1, icuCaseFunc16},
    {"like", 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, 0, icuLikeFunc},
    {"like", 3, SQLITE_UTF8 | SQLITE_DETERMINISTIC, 0, icuLikeFunc},
    // Extra functions
    {"icu_version", 0, SQLITE_UTF8, u_getVersion, icuVersionFunc},
    {"unicode_version", 0, SQLITE_UTF8, u_getUnicodeVersion, icuVersionFunc},
    {"regexp_like", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpLikeFunc},
    {"regexp_like", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpLikeFunc},
    {"icu_regexp_like", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpLikeFunc},
    {"icu_regexp_like", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpLikeFunc},
    {"regexp_instr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"regexp_instr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"regexp_instr", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"regexp_instr", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"regexp_instr", 6, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"icu_regexp_instr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"icu_regexp_instr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"icu_regexp_instr", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"icu_regexp_instr", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"icu_regexp_instr", 6, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpInstrFunc},
    {"regexp_replace", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"regexp_replace", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"regexp_replace", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"regexp_replace", 6, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"icu_regexp_replace", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"icu_regexp_replace", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"icu_regexp_replace", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"icu_regexp_replace", 6, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpRepFunc},
    {"regexp_substr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"regexp_substr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"regexp_substr", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"regexp_substr", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"icu_regexp_substr", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"icu_regexp_substr", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"icu_regexp_substr", 4, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"icu_regexp_substr", 5, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuRegexpSubstrFunc},
    {"title", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuTitleFunc16},
    {"initcap", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuTitleFunc16},
    {"title", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuTitleFunc16},
    {"casefold", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuCaseFoldFunc16},
    {"to_ascii", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
     icuStripAccentsFunc},
#if 0
      {"to_ascii2", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0,
       icuStripAccents2Func},
#endif
    {"scsu_compress", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, &master_scsu,
     icuCompressFunc},
    {"bocu_compress", 1, SQLITE_UTF16 | SQLITE_DETERMINISTIC, &master_bocu1,
     icuCompressFunc},
    {"scsu_decompress", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, &master_scsu,
     icuDecompressFunc},
    {"bocu_decompress", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, &master_bocu1,
     icuDecompressFunc},
    {"normalize", 2, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuNormFunc16},
    {"repeat", 3, SQLITE_UTF16 | SQLITE_DETERMINISTIC, 0, icuRepeatFunc16},

    {"char_name", 1, SQLITE_UTF8, 0, icuCharName8},
    {"char_name", 1, SQLITE_UTF16, 0, icuCharName16},

  };
  int rc = SQLITE_OK;

  for (int i = 0;
       rc == SQLITE_OK && i < (int)(sizeof(scalars) / sizeof(scalars[0]));
       i++) {
    const struct IcuScalar *p = &scalars[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg, p->enc, p->iContext,
                                 p->xFunc, 0, 0);
  }

  return rc;
}

extern int sf_more_init(sqlite3 *);
extern int sf_egc_init(sqlite3 *);

#ifdef _WIN32
__declspec(dllexport)
#endif
    int sqlite3_stringfuncs_init(sqlite3 *db, char **pzErrMsg,
                                 const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);

  UErrorCode status = U_ZERO_ERROR;

  master_scsu = ucnv_open("SCSU", &status);
  if (U_FAILURE(status)) {
    if (pzErrMsg) {
      *pzErrMsg =
          sqlite3_mprintf("ICU error: ucnv_open(): %s", u_errorName(status));
    }
    return SQLITE_ERROR;
  }

  master_bocu1 = ucnv_open("BOCU-1", &status);
  if (U_FAILURE(status)) {
    if (pzErrMsg) {
      *pzErrMsg =
          sqlite3_mprintf("ICU error: ucnv_open(): %s", u_errorName(status));
    }
    return SQLITE_ERROR;
  }

  int rc = sqlite3IcuExtInitFuncs(db);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sf_egc_init(db);
  if (rc != SQLITE_OK) {
    return rc;
  }

  rc = sf_more_init(db);
  if (rc != SQLITE_OK) {
    return rc;
  }

  // Normalization concat functions
  for (int n = 0; n < 4; n += 1) {
    UErrorCode status = U_ZERO_ERROR;
    rc = sqlite3_create_function(
        db, normalizers[n].name, -1, SQLITE_UTF16 | SQLITE_DETERMINISTIC,
        (void *)normalizers[n].f(&status), icuNormConcatFunc16, NULL, NULL);
    if (U_FAILURE(status)) {
      if (pzErrMsg) {
        *pzErrMsg = sqlite3_mprintf("ICU error: %s(): %s", normalizers[n].fname,
                                    u_errorName(status));
      }
      return SQLITE_ERROR;
    }
    if (rc != SQLITE_OK) {
      return rc;
    }

    char *ws_name = sqlite3_mprintf("%s_ws", normalizers[n].name);
    rc = sqlite3_create_function(
        db, ws_name, -1, SQLITE_UTF16 | SQLITE_DETERMINISTIC,
        (void *)normalizers[n].f(&status), icuNormConcatWSFunc16, NULL, NULL);
    sqlite3_free(ws_name);
    if (U_FAILURE(status)) {
      if (pzErrMsg) {
        *pzErrMsg = sqlite3_mprintf("ICU error: %s(): %s", normalizers[n].fname,
                                    u_errorName(status));
      }
      return SQLITE_ERROR;
    }
    if (rc != SQLITE_OK) {
      return rc;
    }
  }

  sqlite3_create_collation(db, "CODEPOINT", SQLITE_UTF16, NULL,
                           icuCodepointCmp);
  sqlite3_create_collation(db, "UNOCASE", SQLITE_UTF16, NULL, icuNoCaseCmp);
  sqlite3_create_collation(db, "EQUIV", SQLITE_UTF16, NULL, icuEquivCmp);
  sqlite3_create_collation(db, "ENOCASE", SQLITE_UTF16, (void *)1, icuEquivCmp);

  return SQLITE_OK;
}
