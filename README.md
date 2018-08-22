Useful (?) Sqlite3 Extensions
=============================

A handful of hopefully useful Sqlite3 extensions. Written mostly as a
way to get more familiar with the extension frameworks. See the files
in the *docs/* directory for details on individual extensions.

* string_funcs - Lots of extra Unicode-aware text handling functions.
* math_funcs - Assorted floating-point functions.
* nss_tables - Interfaces to */etc/passwd* etc.

Build Instructions
------------------

    % mkdir build
    % cd build
    % cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ../src
    % make
    % sqlite3
    sqlite3> .load ./libstring_funcs
    sqlite3> SELECT regexp_substr('abc def ghi', '[a-z]{3}', 1, 2);
    etc.

cmake will only build extensions that satisfy dependencies (No ICU dev
package installed, no libstring_funcs, for example).

A C99 compiler and standard library is required.

To-Do
-----

* Actually add configure tests for nss_tables.
* Some of the string functions do a lot of reallocation and could
  stand to be improved.
* Test cases!
* Add more stuff.

License
-------

MIT.

         
