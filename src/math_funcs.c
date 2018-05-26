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

/* Math functions */

#include <math.h>
#include <stdlib.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

static void mf_deg(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    double r = sqlite3_value_double(apArg[0]);
    sqlite3_result_double(p, r * (180.0 / M_PI));
  }
}

static void mf_rad(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    double d = sqlite3_value_double(apArg[0]);
    sqlite3_result_double(p, d * (M_PI / 180.0));
  }
}

static void mf_acos(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, acos(sqlite3_value_double(apArg[0])));
  }
}

static void mf_asin(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, asin(sqlite3_value_double(apArg[0])));
  }
}

static void mf_atan(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, atan(sqlite3_value_double(apArg[0])));
  }
}

static void mf_atan2(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    sqlite3_result_double(p, atan2(sqlite3_value_double(apArg[0]),
                                   sqlite3_value_double(apArg[1])));
  }
}

static void mf_cos(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, cos(sqlite3_value_double(apArg[0])));
  }
}

static void mf_sin(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, sin(sqlite3_value_double(apArg[0])));
  }
}

static void mf_tan(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, tan(sqlite3_value_double(apArg[0])));
  }
}

static void mf_cot(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, 1.0 / tan(sqlite3_value_double(apArg[0])));
  }
}

static void mf_cbrt(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, cbrt(sqlite3_value_double(apArg[0])));
  }
}

static void mf_exp(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, exp(sqlite3_value_double(apArg[0])));
  }
}

static void mf_log(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, log(sqlite3_value_double(apArg[0])));
  }
}

static void mf_log10(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, log10(sqlite3_value_double(apArg[0])));
  }
}

static void mf_log2(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, log2(sqlite3_value_double(apArg[0])));
  }
}

static void mf_logb(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    sqlite3_result_double(p, log(sqlite3_value_double(apArg[0])) /
                                 log(sqlite3_value_double(apArg[1])));
  }
}

static void mf_pow(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    sqlite3_result_double(
        p, pow(sqlite3_value_double(apArg[0]), sqlite3_value_double(apArg[1])));
  }
}

static void mf_sqrt(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, sqrt(sqlite3_value_double(apArg[0])));
  }
}

static void mf_ceil(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, ceil(sqlite3_value_double(apArg[0])));
  }
}

static void mf_floor(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, floor(sqlite3_value_double(apArg[0])));
  }
}

static void mf_round(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, round(sqlite3_value_double(apArg[0])));
  }
}

static void mf_trunc(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, trunc(sqlite3_value_double(apArg[0])));
  }
}

static void mf_div(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    lldiv_t d =
        lldiv(sqlite3_value_int64(apArg[0]), sqlite3_value_int64(apArg[1]));
    sqlite3_result_int64(p, d.quot);
  }
}

static void mf_mod(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    lldiv_t d =
        lldiv(sqlite3_value_int64(apArg[0]), sqlite3_value_int64(apArg[1]));
    sqlite3_result_int64(p, d.rem);
  }
}

static void mf_sign(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    int t = sqlite3_value_numeric_type(apArg[0]);
    sqlite3_int64 s = 0;
    if (t == SQLITE_FLOAT) {
      s = signbit(sqlite3_value_double(apArg[0]));
    } else if (t == SQLITE_INTEGER) {
      s = sqlite3_value_int64(apArg[0]);
    }
    if (s < 0) {
      s = -1;
    } else if (s > 0) {
      s = 1;
    }
    sqlite3_result_int(p, s);
  }
}

static void mf_pi(sqlite3_context *p, int nArg __attribute__((unused)),
                  sqlite3_value **apArg __attribute__((unused))) {
  sqlite3_result_double(p, M_PI);
}

struct bit_agg {
  sqlite3_uint64 val;
  _Bool init;
  _Bool hasvals;
};

static void mf_bit_or_step(sqlite3_context *p, int nArg __attribute__((unused)),
                      sqlite3_value **apArg)
{
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    c->val |= sqlite3_value_int64(apArg[0]);
    c->hasvals = 1;
  }
}

static void mf_bit_xor_step(sqlite3_context *p, int nArg __attribute__((unused)),
                      sqlite3_value **apArg)
{
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    c->val ^= sqlite3_value_int64(apArg[0]);
    c->hasvals = 1;
  }
}

static void mf_bit_and_step(sqlite3_context *p, int nArg __attribute__((unused)),
                      sqlite3_value **apArg)
{
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (!c->init) {
    c->init = 1;
    c->val = ~((sqlite3_uint64)0);
  }
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
      c->val &= sqlite3_value_int64(apArg[0]);
      c->hasvals = 1;
  }
}

static void mf_bit_final(sqlite3_context *p)
{
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (c->hasvals) {
    sqlite3_result_int64(p, c->val);
  }
}


#ifdef _WIN32
__declspec(dllexport)
#endif
    int sqlite3_mathfuncs_init(sqlite3 *db,
                               char **pzErrMsg __attribute__((unused)),
                               const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);

  const struct MathScalar {
    const char *zName;  /* Function name */
    unsigned char nArg; /* Number of arguments */
    void (*xFunc)(sqlite3_context *, int, sqlite3_value **);
  } scalars[] = {
      {"acos", 1, mf_acos},   {"asin", 1, mf_asin},   {"atan", 1, mf_atan},
      {"atan", 2, mf_atan2},  {"atan2", 2, mf_atan2}, {"cos", 1, mf_cos},
      {"cot", 1, mf_cot},     {"sin", 1, mf_sin},     {"tan", 1, mf_tan},
      {"degrees", 1, mf_deg}, {"radians", 1, mf_rad},

      {"cbrt", 1, mf_cbrt},   {"exp", 1, mf_exp},     {"ln", 1, mf_log},
      {"log", 1, mf_log},     {"log", 2, mf_logb},    {"log10", 1, mf_log10},
      {"log2", 1, mf_log2},   {"power", 2, mf_pow},   {"sqrt", 1, mf_sqrt},

      {"ceil", 1, mf_ceil},   {"floor", 1, mf_floor}, {"round", 1, mf_round},
      {"trunc", 1, mf_trunc},

      {"div", 2, mf_div},     {"mod", 2, mf_mod},     {"sign", 1, mf_sign},
      {"pi", 0, mf_pi},

  };
  const struct MathAgg {
    const char *zName;  /* Function name */
    unsigned char nArg; /* Number of arguments */
    void (*xStep)(sqlite3_context *, int, sqlite3_value **);
    void (*xFinal)(sqlite3_context *);
  } aggs[] = {

        {"bit_or", 1, mf_bit_or_step, mf_bit_final},
        {"bit_xor", 1, mf_bit_xor_step, mf_bit_final},
        {"bit_and", 1, mf_bit_and_step, mf_bit_final},
  };
  int rc = SQLITE_OK;

  for (int i = 0;
       rc == SQLITE_OK && i < (int)(sizeof(scalars) / sizeof(scalars[0]));
       i++) {
    const struct MathScalar *p = &scalars[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 p->xFunc, 0, 0);
  }

  for (int i = 0;
       rc == SQLITE_OK && i < (int)(sizeof(aggs) / sizeof(aggs[0]));
       i++) {
    const struct MathAgg *p = &aggs[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 NULL, p->xStep, p->xFinal);
  }

  return rc;
}
