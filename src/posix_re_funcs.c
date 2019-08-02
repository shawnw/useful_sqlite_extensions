#include "config.h"
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>
#include "sqlite3.h"
#include "sqlite3ext.h"

SQLITE_EXTENSION_INIT1

struct posix_re_cache {
  regex_t re;
};

static void posix_re_delete(void *v) {
  struct posix_re_cache *re = v;
  regfree(&re->re);
}

static void posix_regexp(sqlite3_context *ctx, sqlite3_value **args, int cflags) {
  if (sqlite3_value_type(args[0]) == SQLITE_NULL ||
      sqlite3_value_type(args[1]) == SQLITE_NULL) {
    return;
  }

  struct posix_re_cache *c = sqlite3_get_auxdata(ctx, 0);
  if (!c) {
    c = sqlite3_malloc(sizeof *c);
    if (!c) {
      sqlite3_result_error_nomem(ctx);
      return;
    }
    const char *regex = (const char *)sqlite3_value_text(args[0]);
    int err = regcomp(&c->re, regex, cflags | REG_NOSUB);
    if (err != 0) {
      char errbuff[512];
      regerror(err, &c->re, errbuff, sizeof errbuff);
      sqlite3_result_error(ctx, errbuff, -1);
      sqlite3_free(c);
      return;
    }
    sqlite3_set_auxdata(ctx, 0, c, posix_re_delete);
  }

  const char *str = (const char *)sqlite3_value_text(args[1]);
  int rc = regexec(&c->re, str, 0, NULL, 0);
  if (rc == 0 || rc == REG_NOMATCH) {
    sqlite3_result_int(ctx, rc == 0);
  } else {
    char errbuff[512];
    regerror(rc, &c->re, errbuff, sizeof errbuff);
    sqlite3_result_error(ctx, errbuff, -1);
  }
}


static void ere_func(sqlite3_context *ctx, int nargs __attribute__((unused)),
                       sqlite3_value **args) {
  posix_regexp(ctx, args, REG_EXTENDED);
}

static void bre_func(sqlite3_context *ctx, int nargs __attribute__((unused)),
                       sqlite3_value **args) {
  posix_regexp(ctx, args, 0);
}

#ifdef _WIN32
__declspec(export)
#endif
int sqlite3_posixrefuncs_init(sqlite3 *db, char **pzErrMsg __attribute__((unused)),
                              const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);
  struct re_funcs {
    const char *name;
    void (*fp)(sqlite3_context *, int, sqlite3_value **);
  } func_table[] = {
    {"regexp", ere_func},
    {"ext_regexp", ere_func},
    {"basic_regexp", bre_func},
    {NULL, NULL}
  };
  for (int n = 0; func_table[n].name; n += 1) {
    int rc = sqlite3_create_function(db, func_table[n].name, 2,
                                     SQLITE_DETERMINISTIC | SQLITE_UTF8,
                                     NULL, func_table[n].fp, NULL, NULL);
    if (rc != SQLITE_OK) {
      return rc;
    }
  }
  return SQLITE_OK;
}
