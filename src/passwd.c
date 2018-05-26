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

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

#include "nss_tables.h"

/* /etc/passwd table */

struct passwd_vtab {
  sqlite3_vtab vtab;
};

struct passwd_cursor {
  sqlite3_vtab *vtab;
  struct passwd *pw;
  struct passwd pwstorage;
  char *buf;
  int bufsize;
  _Bool specific;
};

static int passwd_connect(sqlite3 *db, void *pAux __attribute__((unused)),
                          int argc __attribute__((unused)),
                          const char *const *argv __attribute__((unused)),
                          sqlite3_vtab **ppVTab, char **pzErr) {
  int status;
  status = sqlite3_declare_vtab(
      db, "CREATE TABLE etc_passwd(name TEXT NOT NULL, password TEXT, uid INTEGER "
          "NOT NULL, gid INTEGER NOT NULL, gecos TEXT, homedir "
          "TEXT, shell TEXT)");
  if (status != SQLITE_OK) {
    *pzErr = sqlite3_mprintf("%s", sqlite3_errstr(status));
    return SQLITE_ERROR;
  }

  *ppVTab = sqlite3_malloc(sizeof(struct passwd_vtab));
  (*ppVTab)->pModule = &passwd_funcs;
  (*ppVTab)->nRef = 0;
  (*ppVTab)->zErrMsg = NULL;
  return SQLITE_OK;
}

static int passwd_bestindex(sqlite3_vtab *tab __attribute__((unused)),
                            sqlite3_index_info *info) {
  info->idxNum = 0;
  for (int n = 0; n < info->nConstraint; n += 1) {
    if (info->aConstraint[n].usable == 0) {
      continue;
    }
    if (info->aConstraint[n].iColumn == -1 ||
        info->aConstraint[n].iColumn == 2) {
      if (info->aConstraint[n].op == SQLITE_INDEX_CONSTRAINT_EQ) {
        info->idxNum |= 1;
        info->aConstraintUsage[n].argvIndex = 1;
        info->aConstraintUsage[n].omit = 1;
      }
    } else if (info->aConstraint[n].iColumn == 0) {
      if (info->aConstraint[n].op == SQLITE_INDEX_CONSTRAINT_EQ) {
        info->idxNum |= 2;
        info->aConstraintUsage[n].argvIndex = 1;
        info->aConstraintUsage[n].omit = 1;
      }
    }
  }
  if (info->idxNum) {
    info->estimatedCost = 10;
    info->estimatedRows = 1;
    info->idxFlags = SQLITE_INDEX_SCAN_UNIQUE;
  } else {
    info->estimatedCost = 200;
  }
  return SQLITE_OK;
}

static int passwd_disconnect(sqlite3_vtab *tab) {
  sqlite3_free(tab);
  return SQLITE_OK;
}

static int passwd_open(sqlite3_vtab *tab, sqlite3_vtab_cursor **curs) {
  struct passwd_cursor *c = sqlite3_malloc(sizeof(struct passwd_cursor));
  if (!c) {
    if (tab->zErrMsg) {
      sqlite3_free(tab->zErrMsg);
    }
    tab->zErrMsg = sqlite3_mprintf("Out of memory");
    return SQLITE_NOMEM;
  }
  c->vtab = tab;

  c->bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (c->bufsize <= 0) {
    c->bufsize = 4096;
  }
  c->buf = sqlite3_malloc(c->bufsize);
  if (!c->buf) {
    if (tab->zErrMsg) {
      sqlite3_free(tab->zErrMsg);
    }
    sqlite3_free(c);
    tab->zErrMsg = sqlite3_mprintf("Out of memory");
    return SQLITE_NOMEM;
  }

  *curs = (sqlite3_vtab_cursor *)c;
  return SQLITE_OK;
}

static int passwd_close(sqlite3_vtab_cursor *vc) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;
  if (!c->specific) {
    endpwent();
  }
  sqlite3_free(c->buf);
  sqlite3_free(c);
  return SQLITE_OK;
}

int passwd_eof(sqlite3_vtab_cursor *vc) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;
  return c->pw == NULL;
}

static int passwd_filter(sqlite3_vtab_cursor *vc, int idxNum,
                         const char *idxStr __attribute__((unused)),
                         int argc __attribute__((unused)),
                         sqlite3_value **argv) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;

  if (idxNum == 3) {
    if (c->vtab->zErrMsg) {
      sqlite3_free(c->vtab->zErrMsg);
    }
    c->vtab->zErrMsg = sqlite3_mprintf("cannot search for a uid AND username");
    return SQLITE_CONSTRAINT_VTAB;
  }

  if (idxNum == 1) {
    uid_t uid = sqlite3_value_int(argv[0]);
    c->specific = 1;
    while (1) {
      if (getpwuid_r(uid, &(c->pwstorage), c->buf, c->bufsize, &(c->pw)) < 0) {
        if (errno == ERANGE) {
          c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
          c->bufsize *= 2;
        } else if (errno == ENOENT || errno == ESRCH) {
          break;
        } else {
          if (c->vtab->zErrMsg) {
            sqlite3_free(c->vtab->zErrMsg);
          }
          c->vtab->zErrMsg = sqlite3_mprintf("getpwuid_r: %s", strerror(errno));
          return SQLITE_ERROR;
        }
      } else {
        break;
      }
    }
    return SQLITE_OK;
  }

  if (idxNum == 2) {
    const char *username = (const char *)sqlite3_value_text(argv[0]);
    c->specific = 1;
    while (1) {
      if (getpwnam_r(username, &(c->pwstorage), c->buf, c->bufsize, &(c->pw)) <
          0) {
        if (errno == ERANGE) {
          c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
          c->bufsize *= 2;
        } else if (errno == ENOENT || errno == ESRCH) {
          break;
        } else {
          if (c->vtab->zErrMsg) {
            sqlite3_free(c->vtab->zErrMsg);
          }
          c->vtab->zErrMsg = sqlite3_mprintf("getpwnam_r: %s", strerror(errno));
          return SQLITE_ERROR;
        }
      } else {
        break;
      }
    }
    return SQLITE_OK;
  }

  setpwent();
  c->specific = 0;
  while (1) {
    if (getpwent_r(&(c->pwstorage), c->buf, c->bufsize, &(c->pw)) < 0) {
      if (errno == ERANGE) {
        c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
        c->bufsize *= 2;
      } else if (errno == ENOENT || errno == ESRCH) {
        break;
      } else {
        if (c->vtab->zErrMsg) {
          sqlite3_free(c->vtab->zErrMsg);
        }
        c->vtab->zErrMsg = sqlite3_mprintf("getpwent_r: %s", strerror(errno));
        return SQLITE_ERROR;
      }
    } else {
      break;
    }
  }
  return SQLITE_OK;
}

static int passwd_next(sqlite3_vtab_cursor *vc) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;

  if (c->specific) {
    c->pw = NULL;
    return SQLITE_OK;
  }

  while (1) {
    if (getpwent_r(&(c->pwstorage), c->buf, c->bufsize, &(c->pw)) < 0) {
      if (errno == ERANGE) {
        c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
        c->bufsize *= 2;
      } else {
        if (c->vtab->zErrMsg) {
          sqlite3_free(c->vtab->zErrMsg);
        }
        c->vtab->zErrMsg = sqlite3_mprintf("getpwent_r: %s", strerror(errno));
        return SQLITE_ERROR;
      }
    } else {
      break;
    }
  }
  return SQLITE_OK;
}

static int passwd_column(sqlite3_vtab_cursor *vc, sqlite3_context *p, int n) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;
  switch (n) {
  case 0:
    sqlite3_result_text(p, c->pw->pw_name, -1, SQLITE_TRANSIENT);
    break;
  case 1:
    if (c->pw->pw_passwd) {
      sqlite3_result_text(p, c->pw->pw_passwd, -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_result_null(p);
    }
    break;
  case 2:
    sqlite3_result_int(p, c->pw->pw_uid);
    break;
  case 3:
    sqlite3_result_int(p, c->pw->pw_gid);
    break;
  case 4:
    if (c->pw->pw_gecos) {
      sqlite3_result_text(p, c->pw->pw_gecos, -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_result_null(p);
    }
    break;
  case 5:
    if (c->pw->pw_dir) {
      sqlite3_result_text(p, c->pw->pw_dir, -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_result_null(p);
    }
    break;
  case 6:
    if (c->pw->pw_shell) {
      sqlite3_result_text(p, c->pw->pw_shell, -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_result_null(p);
    }
    break;
  default:
    if (c->vtab->zErrMsg) {
      sqlite3_free(c->vtab->zErrMsg);
    }
    c->vtab->zErrMsg = sqlite3_mprintf("Column out of range");
    return SQLITE_RANGE;
  }
  return SQLITE_OK;
}

static int passwd_rowid(sqlite3_vtab_cursor *vc, sqlite3_int64 *pRowId) {
  struct passwd_cursor *c = (struct passwd_cursor *)vc;
  *pRowId = c->pw->pw_uid;
  return SQLITE_OK;
}

static int passwd_rename(sqlite3_vtab *tab __attribute__((unused)),
                         const char *newname __attribute__((unused))) {
  return SQLITE_OK;
}

struct sqlite3_module passwd_funcs = {1,
                                      passwd_connect,
                                      passwd_connect,
                                      passwd_bestindex,
                                      passwd_disconnect,
                                      passwd_disconnect,
                                      passwd_open,
                                      passwd_close,
                                      passwd_filter,
                                      passwd_next,
                                      passwd_eof,
                                      passwd_column,
                                      passwd_rowid,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      passwd_rename,
                                      NULL,
                                      NULL,
                                      NULL};
