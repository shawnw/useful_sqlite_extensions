Useful (?) Sqlite3 Stuff
========================

Extensions
----------

A handful of hopefully useful Sqlite3 extensions. Written mostly as a
way to get more familiar with the extension frameworks. See the files
in the *docs/* directory for details on individual extensions.

* **string_funcs** - Lots of extra Unicode-aware text handling functions
  and more. Includes all of the standard ICU module as well.
* **math_funcs** - Assorted floating-point functions.
* **blob_funcs** - Assorted functions that act on blobs.
* **pcre2_funcs** - Regular expressions using PCRE2
* **posix_re_funcs** - Regular expressions using POSIX Extended and Basic syntax.
* **json_funcs** - Extra JSON functions.
* **bloom_filter1** - Bloom filter indexes.

### Build Instructions ###

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

Tools
-----

Assorted scripts in the `tools/` directory. See the
[README](tools/README.md) there for details.

* **csv2sqlite** - Import CSV files into SQLite databases.
* **table2sql** - Convert ASCII art tables to SQL statements.

To-Do
-----

* Some of the string functions do a lot of reallocation and could
  stand to be improved.
* Test cases!
* Add more stuff.

License
-------

MIT.
