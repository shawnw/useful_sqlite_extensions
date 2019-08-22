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

/* Math functions. Assumes a C99 conforming standard library. */

#include <math.h>
#include <stdlib.h>
#include <string.h>

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

static void mf_acosh(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, acosh(sqlite3_value_double(apArg[0])));
  }
}

static void mf_asinh(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, asinh(sqlite3_value_double(apArg[0])));
  }
}

static void mf_atanh(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, atanh(sqlite3_value_double(apArg[0])));
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

static void mf_cosh(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, cosh(sqlite3_value_double(apArg[0])));
  }
}

static void mf_sinh(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, sinh(sqlite3_value_double(apArg[0])));
  }
}

static void mf_tanh(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, tanh(sqlite3_value_double(apArg[0])));
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

static void mf_expm1(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, expm1(sqlite3_value_double(apArg[0])));
  }
}

static void mf_exp2(sqlite3_context *p, int nArg __attribute__((unused)),
                    sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, exp2(sqlite3_value_double(apArg[0])));
  }
}

static void mf_log(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, log(sqlite3_value_double(apArg[0])));
  }
}

static void mf_log1p(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    sqlite3_result_double(p, log1p(sqlite3_value_double(apArg[0])));
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

static void mf_hypot(sqlite3_context *p, int nArg __attribute__((unused)),
                     sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    sqlite3_result_double(p, hypot(sqlite3_value_double(apArg[0]),
                                   sqlite3_value_double(apArg[1])));
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
    sqlite3_int64 quot =
        sqlite3_value_int64(apArg[0]) / sqlite3_value_int64(apArg[1]);
    sqlite3_result_int64(p, quot);
  }
}

static void mf_mod(sqlite3_context *p, int nArg __attribute__((unused)),
                   sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL &&
      sqlite3_value_type(apArg[1]) != SQLITE_NULL) {
    sqlite3_int64 rem =
        sqlite3_value_int64(apArg[0]) % sqlite3_value_int64(apArg[1]);
    sqlite3_result_int64(p, rem);
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

#ifdef __GNUC__
#if (defined(__x86_64) || defined(__i386))
__attribute__((target("popcnt"))) static void
mf_bitcount_hw(sqlite3_context *ctx, int nargs __attribute__((unused)),
               sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  sqlite3_uint64 n = sqlite3_value_int64(args[0]);
  sqlite3_result_int(ctx, __builtin_popcountll(n));
}
#endif

static void mf_bitcount_sw(sqlite3_context *ctx,
                           int nargs __attribute__((unused)),
                           sqlite3_value **args) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL) {
    return;
  }
  sqlite3_uint64 n = sqlite3_value_int64(args[0]);
  sqlite3_result_int(ctx, __builtin_popcountll(n));
}

#endif

/* Aggregate functions */

struct prod_agg {
  double val;
  sqlite3_int64 count;
};

static void
mf_prod_step(sqlite3_context *p, int nArg __attribute__((unused)),
             sqlite3_value **apArg) {

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  struct prod_agg *prod = sqlite3_aggregate_context(p, sizeof *prod);
  if (!prod) {
    sqlite3_result_error_nomem(p);
    return;
  }

  if (!prod->count) {
    prod->val = sqlite3_value_double(apArg[0]);
    prod->count = 1;
  } else {
    prod->val *= sqlite3_value_double(apArg[0]);
    prod->count += 1;
  }
}

static void mf_prod_final(sqlite3_context *p) {
  struct prod_agg *prod = sqlite3_aggregate_context(p, 0);
  if (!prod || !prod->count) {
    return;
  }
  sqlite3_result_double(p, prod->val);
}

static void mf_prod_inverse(sqlite3_context *p,
                            int nArg __attribute__((unused)),
                            sqlite3_value **apArg) {
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  struct prod_agg *prod = sqlite3_aggregate_context(p, 0);
  if (!prod) {
    return;
  }
  prod->val /= sqlite3_value_double(apArg[0]);
  prod->count -= 1;
}

struct bit_agg {
  sqlite3_uint64 val;
  _Bool init;
  _Bool hasvals;
};

static void mf_bit_or_step(sqlite3_context *p, int nArg __attribute__((unused)),
                           sqlite3_value **apArg) {
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (!c) {
    sqlite3_result_error_nomem(p);
    return;
  }

  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    c->val |= sqlite3_value_int64(apArg[0]);
    c->hasvals = 1;
  }
}

static void mf_bit_xor_step(sqlite3_context *p,
                            int nArg __attribute__((unused)),
                            sqlite3_value **apArg) {
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (!c) {
    sqlite3_result_error_nomem(p);
    return;
  }

  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    c->val ^= sqlite3_value_int64(apArg[0]);
    c->hasvals = 1;
  }
}

static void mf_bit_and_step(sqlite3_context *p,
                            int nArg __attribute__((unused)),
                            sqlite3_value **apArg) {
  struct bit_agg *c = sqlite3_aggregate_context(p, sizeof *c);
  if (!c) {
    sqlite3_result_error_nomem(p);
    return;
  }

  if (!c->init) {
    c->init = 1;
    c->val = ~((sqlite3_uint64)0);
  }
  if (sqlite3_value_type(apArg[0]) != SQLITE_NULL) {
    c->val &= sqlite3_value_int64(apArg[0]);
    c->hasvals = 1;
  }
}

static void mf_bit_final(sqlite3_context *p) {
  struct bit_agg *c = sqlite3_aggregate_context(p, 0);
  if (!c) {
    return;
  }

  if (c->hasvals) {
    sqlite3_result_int64(p, c->val);
  }
}

struct covariance {
  double xsum;
  double ysum;
  double xysum;
  size_t n;
  _Bool init;
};

static void mf_covar_step(sqlite3_context *ctx,
                          int nArg __attribute__((unused)),
                          sqlite3_value **apArg) {
  struct covariance *cv = sqlite3_aggregate_context(ctx, sizeof *cv);
  if (!cv) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!cv->init) {
    cv->ysum = 0.0;
    cv->xsum = 0.0;
    cv->xysum = 0.0;
    cv->n = 0;
    cv->init = 1;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  double y = sqlite3_value_double(apArg[0]);
  double x = sqlite3_value_double(apArg[1]);

  cv->ysum += y;
  cv->xsum += x;
  cv->xysum += x * y;
  cv->n += 1;
}

static void mf_covar_inverse(sqlite3_context *ctx,
                             int nArg __attribute__((unused)),
                             sqlite3_value **apArg) {
  struct covariance *cv = sqlite3_aggregate_context(ctx, sizeof *cv);
  if (!cv) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!cv->init) {
    cv->ysum = 0.0;
    cv->xsum = 0.0;
    cv->xysum = 0.0;
    cv->n = 0;
    cv->init = 1;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL ||
      sqlite3_value_type(apArg[1]) == SQLITE_NULL) {
    return;
  }

  double y = sqlite3_value_double(apArg[0]);
  double x = sqlite3_value_double(apArg[1]);

  cv->ysum -= y;
  cv->xsum -= x;
  cv->xysum -= x * y;
  cv->n -= 1;
}

static void mf_covar_samp(sqlite3_context *ctx) {
  struct covariance *cv = sqlite3_aggregate_context(ctx, 0);
  if (!cv || !cv->init || cv->n <= 1) {
    return;
  }
  sqlite3_result_double(ctx, (cv->xysum - cv->ysum * cv->xsum / cv->n) /
                                 (cv->n - 1));
}

static void mf_covar_pop(sqlite3_context *ctx) {
  struct covariance *cv = sqlite3_aggregate_context(ctx, 0);
  if (!cv || !cv->init || cv->n == 0) {
    return;
  }
  sqlite3_result_double(ctx, (cv->xysum - cv->ysum * cv->xsum / cv->n) / cv->n);
}

struct variance {
  double a;
  double q;
  size_t n;
  _Bool init;
};

static void mf_var_step(sqlite3_context *ctx, int nArg __attribute__((unused)),
                        sqlite3_value **apArg) {
  struct variance *v = sqlite3_aggregate_context(ctx, sizeof *v);
  if (!v) {
    sqlite3_result_error_nomem(ctx);
    return;
  }

  if (!v->init) {
    v->a = 0.0;
    v->q = 0.0;
    v->n = 0;
    v->init = 1;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  v->n += 1;
  double x = sqlite3_value_double(apArg[0]);
  double a = v->a + (x - v->a) / v->n;
  double q = v->q + (x - v->a) * (x - a);
  v->a = a;
  v->q = q;
}

static void mf_stddev_samp(sqlite3_context *ctx) {
  struct variance *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->n <= 1) {
    return;
  }
  sqlite3_result_double(ctx, sqrt(v->q / (v->n - 1)));
}

static void mf_stddev_pop(sqlite3_context *ctx) {
  struct variance *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->n == 0) {
    return;
  }
  sqlite3_result_double(ctx, sqrt(v->q / v->n));
}

static void mf_var_samp(sqlite3_context *ctx) {
  struct variance *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->n <= 1) {
    return;
  }
  sqlite3_result_double(ctx, v->q / (v->n - 1));
}

static void mf_var_pop(sqlite3_context *ctx) {
  struct variance *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->n == 0) {
    return;
  }
  sqlite3_result_double(ctx, v->q / v->n);
}

struct mean {
  double total;
  size_t n;
  _Bool init;
};

static void mf_geo_mean_step(sqlite3_context *ctx,
                             int nArg __attribute__((unused)),
                             sqlite3_value **apArg) {
  struct mean *m = sqlite3_aggregate_context(ctx, sizeof *m);
  if (!m) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!m->init) {
    m->init = 1;
    m->n = 0;
    m->total = 1.0;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  m->total *= sqlite3_value_double(apArg[0]);
  m->n += 1;
}

static void mf_geo_mean_inverse(sqlite3_context *ctx,
                                int nArg __attribute__((unused)),
                                sqlite3_value **apArg) {
  struct mean *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  m->total /= sqlite3_value_double(apArg[0]);
  m->n -= 1;
}

static void mf_geo_mean_final(sqlite3_context *ctx) {
  struct mean *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  sqlite3_result_double(ctx, pow(m->total, 1.0 / m->n));
}

static void mf_harm_mean_step(sqlite3_context *ctx,
                              int nArg __attribute__((unused)),
                              sqlite3_value **apArg) {
  struct mean *m = sqlite3_aggregate_context(ctx, sizeof *m);
  if (!m) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!m->init) {
    m->init = 1;
    m->n = 0;
    m->total = 0;
  }
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }
  m->total += 1.0 / sqlite3_value_double(apArg[0]);
  m->n += 1;
}

static void mf_harm_mean_inverse(sqlite3_context *ctx,
                                 int nArg __attribute__((unused)),
                                 sqlite3_value **apArg) {
  struct mean *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }
  m->total -= 1.0 / sqlite3_value_double(apArg[0]);
  m->n -= 1;
}

static void mf_harm_mean_final(sqlite3_context *ctx) {
  struct mean *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  sqlite3_result_double(ctx, m->n / m->total);
}

struct numarray {
  double *values;
  size_t n;
  size_t capacity;
  _Bool init;
  _Bool sorted;
};

static void mf_numarray_step(sqlite3_context *ctx,
                             int nArg __attribute__((unused)),
                             sqlite3_value **apArg) {
  struct numarray *m = sqlite3_aggregate_context(ctx, sizeof *m);
  if (!m) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!m->init) {
    m->init = 1;
    m->n = 0;
    m->capacity = 100;
    m->values = sqlite3_malloc(sizeof(double) * 100);
    if (!m->values) {
      sqlite3_result_error_nomem(ctx);
      return;
    }
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  if (m->n == m->capacity) {
    double *newvals =
        sqlite3_realloc(m->values, sizeof(double) * ceil(m->capacity * 1.5));
    if (!newvals) {
      sqlite3_result_error_nomem(ctx);
      return;
    }
    m->values = newvals;
    m->capacity = ceil(m->capacity * 1.5);
  }
  m->sorted = 0;
  m->values[m->n++] = sqlite3_value_double(apArg[0]);
}

static void mf_numarray_inverse(sqlite3_context *ctx,
                                int nArg __attribute__((unused)),
                                sqlite3_value **apArg) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  double d = sqlite3_value_double(apArg[0]);

  for (size_t i = 0; i < m->n; i += 1) {
    if (m->values[i] == d) {
      memmove(m->values + i, m->values + i + 1,
              sizeof(double) * (m->n - i - 1));
      m->n -= 1;
      break;
    }
  }
}

static int cmp_double(const void *va, const void *vb) {
  double a = *(double *)va;
  double b = *(double *)vb;
  if (a == b) {
    return 0;
  } else if (a < b) {
    return -1;
  } else {
    return 1;
  }
}

static void mf_median_calc(sqlite3_context *ctx, struct numarray *m) {
  if (m->n == 0) {
    return;
  }

  if (m->n == 1) {
    sqlite3_result_double(ctx, m->values[0]);
    return;
  }

  if (!m->sorted) {
    qsort(m->values, m->n, sizeof(double), cmp_double);
    m->sorted = 1;
  }
  size_t mid = m->n / 2;
  if (m->n & 1) {
    // Odd
    sqlite3_result_double(ctx, m->values[mid]);
  } else {
    // Even
    sqlite3_result_double(ctx, (m->values[mid] + m->values[mid - 1]) / 2.0);
  }
}

static void mf_median_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_median_calc(ctx, m);
  sqlite3_free(m->values);
}

static void mf_median_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_median_calc(ctx, m);
}

static void mf_mode_calc(sqlite3_context *ctx, struct numarray *m) {
  if (m->n == 0) {
    return;
  }

  if (m->n == 1) {
    sqlite3_result_double(ctx, m->values[0]);
    return;
  }

  if (!m->sorted) {
    qsort(m->values, m->n, sizeof(double), cmp_double);
    m->sorted = 1;
  }

  double mode = m->values[0];
  double prev = mode;
  size_t mode_len = 1;
  size_t run_len = 1;

  for (size_t i = 1; i < m->n; i += 1) {
    if (m->values[i] == mode) {
      mode_len += 1;
    }
    if (m->values[i] == prev) {
      run_len += 1;
    } else {
      if (run_len > mode_len) {
        mode = prev;
        mode_len = run_len;
      }
      prev = m->values[i];
      run_len = 1;
    }
  }
  sqlite3_result_double(ctx, mode);
}

static void mf_mode_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_mode_calc(ctx, m);
  sqlite3_free(m->values);
}

static void mf_mode_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_mode_calc(ctx, m);
}

static _Bool mf_quartile_calc(double *d, struct numarray *m, int q) {
  if (m->n == 0) {
    return 0;
  } else if (m->n == 1) {
    *d = m->values[0];
    return 1;
  }

  if (!m->sorted) {
    qsort(m->values, m->n, sizeof(double), cmp_double);
    m->sorted = 1;
  }

  size_t n = m->n;
  size_t left;
  if (n == 2) {
    *d = m->values[q == 1 ? 0 : 1];
    return 1;
  } else if (q == 1) {
    left = 0;
    if (n & 1) {
      n -= 1;
    }
    n /= 2;
  } else {
    if (n & 1) {
      n -= 1;
    }
    n /= 2;
    left = n + 1;
  }

  n /= 2;
  *d = (m->values[left + n] + m->values[left + n - 1]) / 2.0;
  return 1;
}

static void mf_q1_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double d;
  if (mf_quartile_calc(&d, m, 1)) {
    sqlite3_result_double(ctx, d);
  }
  sqlite3_free(m->values);
}

static void mf_q1_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double d;
  if (mf_quartile_calc(&d, m, 1)) {
    sqlite3_result_double(ctx, d);
  }
}

static void mf_q3_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double d;
  if (mf_quartile_calc(&d, m, 3)) {
    sqlite3_result_double(ctx, d);
  }
  sqlite3_free(m->values);
}

static void mf_q3_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double d;
  if (mf_quartile_calc(&d, m, 3)) {
    sqlite3_result_double(ctx, d);
  }
}

static void mf_iqr_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double q1, q3;
  if (mf_quartile_calc(&q1, m, 1) && mf_quartile_calc(&q3, m, 3)) {
    sqlite3_result_double(ctx, q3 - q1);
  }
  sqlite3_free(m->values);
}

static void mf_iqr_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  double q1, q3;
  if (mf_quartile_calc(&q1, m, 1) && mf_quartile_calc(&q3, m, 3)) {
    sqlite3_result_double(ctx, q3 - q1);
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
      {"acosh", 1, mf_acosh}, {"asinh", 1, mf_asinh}, {"atanh", 1, mf_atanh},
      {"atan", 2, mf_atan2},  {"atan2", 2, mf_atan2}, {"cos", 1, mf_cos},
      {"cot", 1, mf_cot},     {"sin", 1, mf_sin},     {"tan", 1, mf_tan},
      {"sinh", 1, mf_sinh},   {"cosh", 1, mf_cosh},   {"tanh", 1, mf_tanh},
      {"degrees", 1, mf_deg}, {"radians", 1, mf_rad},

      {"cbrt", 1, mf_cbrt},   {"exp", 1, mf_exp},     {"expm1", 1, mf_expm1},
      {"exp2", 1, mf_exp2},   {"ln", 1, mf_log},      {"log", 1, mf_log},
      {"log", 2, mf_logb},    {"log1p", 1, mf_log1p}, {"log10", 1, mf_log10},
      {"log2", 1, mf_log2},   {"power", 2, mf_pow},   {"sqrt", 1, mf_sqrt},
      {"hypot", 2, mf_hypot},

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
    void (*xValue)(sqlite3_context *);
    void (*xInverse)(sqlite3_context *, int, sqlite3_value **);
  } aggs[] = {
      {"product", 1, mf_prod_step, mf_prod_final, mf_prod_final,
       mf_prod_inverse},
      {"bit_or", 1, mf_bit_or_step, mf_bit_final, NULL, NULL},
      {"bit_xor", 1, mf_bit_xor_step, mf_bit_final, mf_bit_final,
       mf_bit_xor_step},
      {"bit_and", 1, mf_bit_and_step, mf_bit_final, NULL, NULL},
      {"covar_pop", 2, mf_covar_step, mf_covar_pop, mf_covar_pop,
       mf_covar_inverse},
      {"covar_samp", 2, mf_covar_step, mf_covar_samp, mf_covar_samp,
       mf_covar_inverse},
      {"stddev_pop", 1, mf_var_step, mf_stddev_pop, NULL, NULL},
      {"stddev_samp", 1, mf_var_step, mf_stddev_samp, NULL, NULL},
      {"var_pop", 1, mf_var_step, mf_var_pop, NULL, NULL},
      {"var_samp", 1, mf_var_step, mf_var_samp, NULL, NULL},
      {"geo_mean", 1, mf_geo_mean_step, mf_geo_mean_final, mf_geo_mean_final,
       mf_geo_mean_inverse},
      {"harm_mean", 1, mf_harm_mean_step, mf_harm_mean_final,
       mf_harm_mean_final, mf_harm_mean_inverse},
      {"median", 1, mf_numarray_step, mf_median_final, mf_median_value,
       mf_numarray_inverse},
      {"mode", 1, mf_numarray_step, mf_mode_final, mf_mode_value,
       mf_numarray_inverse},
      {"q1", 1, mf_numarray_step, mf_q1_final, mf_q1_value,
       mf_numarray_inverse},
      {"q3", 1, mf_numarray_step, mf_q3_final, mf_q3_value,
       mf_numarray_inverse},
      {"iqr", 1, mf_numarray_step, mf_iqr_final, mf_iqr_value,
       mf_numarray_inverse},

  };
  int rc = SQLITE_OK;

#if defined(__GNUC__)
#if (defined(__x86_64) || defined(__i386))
  rc = sqlite3_create_function(
      db, "bit_count", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
      __builtin_cpu_supports("popcnt") ? mf_bitcount_hw : mf_bitcount_sw, NULL,
      NULL);
#else
  rc = sqlite3_create_function(db, "bit_count", 1,
                               SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                               mf_bitcount_sw, NULL, NULL);
#endif
  if (rc != SQLITE_OK) {
    return rc;
  }
#endif

  for (int i = 0;
       rc == SQLITE_OK && i < (int)(sizeof(scalars) / sizeof(scalars[0]));
       i++) {
    const struct MathScalar *p = &scalars[i];
    rc = sqlite3_create_function(db, p->zName, p->nArg,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
                                 p->xFunc, 0, 0);
  }

  for (int i = 0; rc == SQLITE_OK && i < (int)(sizeof(aggs) / sizeof(aggs[0]));
       i++) {
    const struct MathAgg *p = &aggs[i];
#if SQLITE_VERSION_NUMBER >= 3025000
    rc = sqlite3_create_window_function(
        db, p->zName, p->nArg, SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL,
        p->xStep, p->xFinal, p->xValue, p->xInverse, NULL);
#else
    rc = sqlite3_create_function(db, p->zName, p->nArg,
                                 SQLITE_UTF8 | SQLITE_DETERMINISTIC, NULL, NULL,
                                 p->xStep, p->xFinal);
#endif
  }

  return rc;
}
