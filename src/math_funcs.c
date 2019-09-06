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

#include <assert.h>
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

struct numarray {
  double *arr;
  size_t capacity;
  size_t used;
  _Bool sorted;
  _Bool init;
};

static _Bool init_numarray(struct numarray *da) {
  da->arr = sqlite3_malloc64(sizeof(double) * 10);
  if (!da->arr) {
    sqlite3_free(da);
    return 0;
  }
  da->used = 0;
  da->capacity = 10;
  da->sorted = 0;
  da->init = 1;
  return 1;
}

void free_numarray(struct numarray *da) {
  assert(da);
  sqlite3_free(da->arr);
}

static _Bool add_dbl(struct numarray *da, double d) {
  assert(da);
  if (da->used >= da->capacity) {
    size_t newcap = da->capacity * 1.5;
    double *newarr = sqlite3_realloc(da->arr, newcap * sizeof(double));
    if (!newarr) {
      return 0;
    }
    da->capacity = newcap;
    da->arr = newarr;
  }
  da->arr[da->used++] = d;
  da->sorted = 0;
  return 1;
}

static _Bool del_dbl(struct numarray *da, double d) {
  assert(da);
  for (size_t i = 0; i < da->used; i += 1) {
    if (da->arr[i] == d) {
      memmove(da->arr + i, da->arr + i + 1,
              sizeof(double) * (da->used - i - 1));
      da->used -= 1;
      return 1;
    }
  }
  return 0;
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

static void sort_numarray(struct numarray *da) {
  assert(da);
  if (da->sorted) {
    return;
  }
  qsort(da->arr, da->used, sizeof(double), cmp_double);
  da->sorted = 1;
}

static double mean_numarray(struct numarray *da) {
  assert(da);
  double m = 0.0;
  sort_numarray(da);
  for (size_t i = 0; i < da->used; i += 1) {
    m += da->arr[i];
  }
  return m / da->used;
}

static void mf_numarray_step(sqlite3_context *ctx,
                             int nArg __attribute__((unused)),
                             sqlite3_value **apArg) {
  assert(nArg == 1);
  struct numarray *m = sqlite3_aggregate_context(ctx, sizeof *m);
  if (!m) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
  if (!m->init) {
    if (!init_numarray(m)) {
      sqlite3_result_error_nomem(ctx);
      return;
    }
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  if (!add_dbl(m, sqlite3_value_double(apArg[0]))) {
    sqlite3_result_error_nomem(ctx);
    return;
  }
}

static void mf_numarray_inverse(sqlite3_context *ctx,
                                int nArg __attribute__((unused)),
                                sqlite3_value **apArg) {
  assert(nArg == 1);
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }

  if (sqlite3_value_type(apArg[0]) == SQLITE_NULL) {
    return;
  }

  del_dbl(m, sqlite3_value_double(apArg[0]));
}

struct prod_agg {
  double val;
  sqlite3_int64 count;
};

static void mf_prod_step(sqlite3_context *p, int nArg __attribute__((unused)),
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

static double var_calc_pop(struct numarray *da) {
  if (da->used == 0) {
    return 0.0;
  }

  double q = 0.0;
  double m = mean_numarray(da);

  for (size_t i = 0; i < da->used; i += 1) {
    double d = da->arr[i] - m;
    q += d * d;
  }
  return q / da->used;
}

static double var_calc_samp(struct numarray *da) {
  if (da->used <= 1) {
    return 0.0;
  }

  double q = 0.0;
  double m = mean_numarray(da);

  for (size_t i = 0; i < da->used; i += 1) {
    double d = da->arr[i] - m;
    q += d * d;
  }
  return q / (da->used - 1);
}

static double stddev_calc_pop(struct numarray *da) {
  return sqrt(var_calc_pop(da));
}

static double stddev_calc_samp(struct numarray *da) {
  return sqrt(var_calc_samp(da));
}

static void mf_stddev_samp_final(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used <= 1) {
    return;
  }

  sqlite3_result_double(ctx, stddev_calc_samp(v));
  free_numarray(v);
}

static void mf_stddev_samp_value(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used <= 1) {
    return;
  }

  sqlite3_result_double(ctx, stddev_calc_samp(v));
}

static void mf_stddev_pop_final(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, stddev_calc_pop(v));
  free_numarray(v);
}

static void mf_stddev_pop_value(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, stddev_calc_pop(v));
}

static void mf_var_samp_final(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, var_calc_samp(v));
  free_numarray(v);
}

static void mf_var_samp_value(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, var_calc_samp(v));
}

static void mf_var_pop_final(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, var_calc_pop(v));
  free_numarray(v);
}

static void mf_var_pop_value(sqlite3_context *ctx) {
  struct numarray *v = sqlite3_aggregate_context(ctx, 0);
  if (!v) {
    return;
  }

  if (!v->init || v->used == 0) {
    return;
  }
  sqlite3_result_double(ctx, var_calc_pop(v));
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

static void mf_median_calc(sqlite3_context *ctx, struct numarray *m) {
  if (m->used == 0) {
    return;
  }

  if (m->used == 1) {
    sqlite3_result_double(ctx, m->arr[0]);
    return;
  }

  sort_numarray(m);
  size_t mid = m->used / 2;
  if (m->used & 1) {
    // Odd
    sqlite3_result_double(ctx, m->arr[mid]);
  } else {
    // Even
    sqlite3_result_double(ctx, (m->arr[mid] + m->arr[mid - 1]) / 2.0);
  }
}

static void mf_median_final(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_median_calc(ctx, m);
  free_numarray(m);
}

static void mf_median_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_median_calc(ctx, m);
}

static void mf_mode_calc(sqlite3_context *ctx, struct numarray *m) {
  if (m->used == 0) {
    return;
  }

  if (m->used == 1) {
    sqlite3_result_double(ctx, m->arr[0]);
    return;
  }

  sort_numarray(m);

  double mode = m->arr[0];
  double prev = mode;
  size_t mode_len = 1;
  size_t run_len = 1;

  for (size_t i = 1; i < m->used; i += 1) {
    if (m->arr[i] == mode) {
      mode_len += 1;
    }
    if (m->arr[i] == prev) {
      run_len += 1;
    } else {
      if (run_len > mode_len) {
        mode = prev;
        mode_len = run_len;
      }
      prev = m->arr[i];
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
  free_numarray(m);
}

static void mf_mode_value(sqlite3_context *ctx) {
  struct numarray *m = sqlite3_aggregate_context(ctx, 0);
  if (!m) {
    return;
  }
  mf_mode_calc(ctx, m);
}

static _Bool mf_quartile_calc(double *d, struct numarray *m, int q) {
  if (m->used == 0) {
    return 0;
  } else if (m->used == 1) {
    *d = m->arr[0];
    return 1;
  }

  sort_numarray(m);

  size_t n = m->used;
  size_t left;
  if (n == 2) {
    *d = m->arr[q == 1 ? 0 : 1];
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
  *d = (m->arr[left + n] + m->arr[left + n - 1]) / 2.0;
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
  free_numarray(m);
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
  free_numarray(m);
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
  free_numarray(m);
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
      {"stddev_pop", 1, mf_numarray_step, mf_stddev_pop_final,
       mf_stddev_pop_value, mf_numarray_inverse},
      {"stddev_samp", 1, mf_numarray_step, mf_stddev_samp_final,
       mf_stddev_samp_value, mf_numarray_inverse},
      {"var_pop", 1, mf_numarray_step, mf_var_pop_final, mf_var_pop_value,
       mf_numarray_inverse},
      {"var_samp", 1, mf_numarray_step, mf_var_samp_final, mf_var_samp_value,
       mf_numarray_inverse},
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
