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

#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT3

#include "nss_tables.h"

/* /etc/group table */

struct group_vtab {
  sqlite3_vtab vtab;
};

struct group_cursor {
  sqlite3_vtab *vtab;
  struct group *gr;
  struct group grstorage;
  char *buf;
  int bufsize;
  int memidx;
  sqlite3_int64 rowid;
  _Bool specific;
};

static int group_connect(sqlite3 *db, void *pAux __attribute__((unused)),
                         int argc __attribute__((unused)),
                         const char *const *argv __attribute__((unused)),
                         sqlite3_vtab **ppVTab, char **pzErr) {
  int status;
  status = sqlite3_declare_vtab(
      db, "CREATE TABLE etc_group(name TEXT NOT NULL, password TEXT, "
          "gid INTEGER NOT NULL, member TEXT)");
  if (status != SQLITE_OK) {
    *pzErr = sqlite3_mprintf("%s", sqlite3_errstr(status));
    return SQLITE_ERROR;
  }

  *ppVTab = sqlite3_malloc(sizeof(struct group_vtab));
  (*ppVTab)->pModule = &group_funcs;
  (*ppVTab)->nRef = 0;
  (*ppVTab)->zErrMsg = NULL;
  return SQLITE_OK;
}

static int group_bestindex(sqlite3_vtab *tab __attribute__((unused)),
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

static int group_disconnect(sqlite3_vtab *tab) {
  sqlite3_free(tab);
  return SQLITE_OK;
}

static int group_open(sqlite3_vtab *tab, sqlite3_vtab_cursor **curs) {
  struct group_cursor *c = sqlite3_malloc(sizeof(struct group_cursor));
  if (!c) {
    if (tab->zErrMsg) {
      sqlite3_free(tab->zErrMsg);
    }
    tab->zErrMsg = sqlite3_mprintf("Out of memory");
    return SQLITE_NOMEM;
  }
  c->vtab = tab;
  c->bufsize = 4096;
  c->buf = sqlite3_malloc(c->bufsize);
  if (!c->buf) {
    if (tab->zErrMsg) {
      sqlite3_free(tab->zErrMsg);
    }
    sqlite3_free(c);
    tab->zErrMsg = sqlite3_mprintf("Out of memory");
    return SQLITE_NOMEM;
  }
  c->rowid = 0;
  
  *curs = (sqlite3_vtab_cursor *)c;
  return SQLITE_OK;
}

static int group_close(sqlite3_vtab_cursor *vc) {
  struct group_cursor *c = (struct group_cursor *)vc;
  if (!c->specific) {
    endgrent();
  }
  sqlite3_free(c->buf);
  sqlite3_free(c);
  return SQLITE_OK;
}

int group_eof(sqlite3_vtab_cursor *vc) {
  struct group_cursor *c = (struct group_cursor *)vc;
  return c->gr == NULL;
}

static int group_filter(sqlite3_vtab_cursor *vc, int idxNum,
                        const char *idxStr __attribute__((unused)),
                        int argc __attribute__((unused)),
                        sqlite3_value **argv) {
  struct group_cursor *c = (struct group_cursor *)vc;

  c->memidx = 0;

  if (idxNum == 3) {
    if (c->vtab->zErrMsg) {
      sqlite3_free(c->vtab->zErrMsg);
    }
    c->vtab->zErrMsg = sqlite3_mprintf("cannot search for a gid AND groupname");
    return SQLITE_CONSTRAINT_VTAB;
  }

  if (idxNum == 1) {
    gid_t gid = sqlite3_value_int(argv[0]);
    c->specific = 1;
    while (1) {
      if (getgrgid_r(gid, &(c->grstorage), c->buf, c->bufsize, &(c->gr)) < 0) {
        if (errno == ERANGE) {
          c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
          c->bufsize *= 2;
        } else if (errno == ENOENT || errno == ESRCH) {
          break;
        } else {
          if (c->vtab->zErrMsg) {
            sqlite3_free(c->vtab->zErrMsg);
          }
          c->vtab->zErrMsg = sqlite3_mprintf("getgrgid_r: %s", strerror(errno));
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
      if (getgrnam_r(username, &(c->grstorage), c->buf, c->bufsize, &(c->gr)) <
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
          c->vtab->zErrMsg = sqlite3_mprintf("getgrnam_r: %s", strerror(errno));
          return SQLITE_ERROR;
        }
      } else {
        break;
      }
    }
    return SQLITE_OK;
  }

  setgrent();
  c->specific = 0;
  while (1) {
    if (getgrent_r(&(c->grstorage), c->buf, c->bufsize, &(c->gr)) < 0) {
      if (errno == ERANGE) {
        c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
        c->bufsize *= 2;
      } else if (errno == ENOENT || errno == ESRCH) {
        break;
      } else {
        if (c->vtab->zErrMsg) {
          sqlite3_free(c->vtab->zErrMsg);
        }
        c->vtab->zErrMsg = sqlite3_mprintf("getgrent_r: %s", strerror(errno));
        return SQLITE_ERROR;
      }
    } else {
      break;
    }
  }
  return SQLITE_OK;
}

static int group_next(sqlite3_vtab_cursor *vc) {
  struct group_cursor *c = (struct group_cursor *)vc;

  // One row per member of the current group
  if (c->gr->gr_mem[c->memidx] != NULL) {
    c->memidx += 1;
    if (c->gr->gr_mem[c->memidx]) {
      c->rowid += 1;
      return SQLITE_OK;
    }
  }

  // EOF if done with members of an indexed group.
  if (c->specific) {
    c->gr = NULL;
    return SQLITE_OK;
  }

  // Get the next group.
  while (1) {
    if (getgrent_r(&(c->grstorage), c->buf, c->bufsize, &(c->gr)) < 0) {
      if (errno == ERANGE) {
        c->buf = sqlite3_realloc(c->buf, c->bufsize * 2);
        c->bufsize *= 2;
      } else {
        if (c->vtab->zErrMsg) {
          sqlite3_free(c->vtab->zErrMsg);
        }
        c->vtab->zErrMsg = sqlite3_mprintf("getgrent_r: %s", strerror(errno));
        return SQLITE_ERROR;
      }
    } else {
      break;
    }
  }
  c->memidx = 0;
  c->rowid += 1;
  return SQLITE_OK;
}

static int group_column(sqlite3_vtab_cursor *vc, sqlite3_context *p, int n) {
  struct group_cursor *c = (struct group_cursor *)vc;
  switch (n) {
  case 0:
    sqlite3_result_text(p, c->gr->gr_name, -1, SQLITE_TRANSIENT);
    break;
  case 1:
    if (c->gr->gr_passwd) {
      sqlite3_result_text(p, c->gr->gr_passwd, -1, SQLITE_TRANSIENT);
    } else {
      sqlite3_result_null(p);
    }
    break;
  case 2:
    sqlite3_result_int(p, c->gr->gr_gid);
    break;
  case 3:
    if (c->gr->gr_mem[c->memidx]) {
      sqlite3_result_text(p, c->gr->gr_mem[c->memidx], -1, SQLITE_TRANSIENT);
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

static int group_rowid(sqlite3_vtab_cursor *vc, sqlite3_int64 *pRowId) {
  struct group_cursor *c = (struct group_cursor *)vc;
  *pRowId = c->rowid;
  return SQLITE_OK;
}

static int group_rename(sqlite3_vtab *tab __attribute__((unused)),
                        const char *newname __attribute__((unused))) {
  return SQLITE_OK;
}

struct sqlite3_module group_funcs = {1,
                                     group_connect,
                                     group_connect,
                                     group_bestindex,
                                     group_disconnect,
                                     group_disconnect,
                                     group_open,
                                     group_close,
                                     group_filter,
                                     group_next,
                                     group_eof,
                                     group_column,
                                     group_rowid,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     group_rename,
                                     NULL,
                                     NULL,
                                     NULL};
