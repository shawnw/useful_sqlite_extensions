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

#include <stdlib.h>

#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

#include "nss_tables.h"

#ifdef _WIN32
__declspec(dllexport)
#endif
    int sqlite3_nsstables_init(sqlite3 *db,
                               char **pzErrMsg __attribute__((unused)),
                               const sqlite3_api_routines *pApi) {
  SQLITE_EXTENSION_INIT2(pApi);

  sqlite3_create_module(db, "etc_passwd", &passwd_funcs, NULL);
  sqlite3_create_module(db, "etc_group", &group_funcs, NULL);

  return SQLITE_OK;
}
