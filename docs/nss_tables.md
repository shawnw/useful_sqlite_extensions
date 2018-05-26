Name Service Switch Tables
==========================

This Sqlite3 extension module provides eponymous virtual tables into
common NSS databases on Unix systems, like */etc/passwd*.

Warning: It is **NOT** thread-safe due to underlying C functions not
being thread safe. Probably won't work on anything but glibc systems.

Tables
------

### etc_passwd

Interface to [/etc/passwd]. Virtual table with the schema:

    CREATE TABLE etc_passwd(name TEXT, password TEXT, uid INTEGER, gid INTEGER, gecos TEXT, userdir TEXT, shell TEXT)

Comparing the name and uid fields to a specific username or uid in a
WHERE clause uses `getpwnam_r()` or `getpwuid_r()`
respectively. Returning the entire file uses
`getpwent_r()`. Unfortunately that doesn't make it fully re-enterant.

[/etc/passwd]: https://linux.die.net/man/5/passwd

### etc_group

Interface to [/etc/group]. Virtual table with the schema:

    CREATE TABLE etc_group(name TEXT, password TEXT, gid INTEGER, member TEXT)

There is one row in the results for each member of a given group. If a
group has no members, it has one row with the `member` column set to
`NULL`.

Comparing the name and gid fields to a specific group name or gid in a
WHERE clause uses `getgrnam_r()` or `getgrgid_r()`
respectively. Returning the entire file uses
`getgrent_r()`. Unfortunately that doesn't make it fully re-enterant.

[/etc/group]: https://linux.die.net/man/5/group

### TO-DO

* */etc/services*
* */etc/protocols*
* Others?
