Introduction
============

A collection of handy scripts that do stuff with Sqlite. Mostly perl,
and thus requiring the [DBD::SQLite] module. Install through your OS
package manager or CPAN.

The Programs
============

csv2sqlite
----------

Import CSV files into Sqlite, in a smarter way than the command line
shell's [CSV import] feature. Requires the [Text::CSV_XS] module.

### Usage ###

    csv2sqlite [OPTIONS] database tablename [FILE]

If a file to import from is not given, reads from standard input. If
the table does not already exist in the database, it's created using
the first line of the CSV input as column names.

### Options ###

* `-t CHAR` What to use as a field separator. Defaults to comma.
* `--primary-key=COLUMN` A comma-separated list of column names to use
   as the primary key when creating a table. Can be abbreviated
   `--pk`. Ignored if importing into an existing table.
* `--ipk` Takes a single column name and treats it as an `INTEGER
  PRIMARY KEY` rowid alias. Can't be used with `--primary-key`.
* `--without-rowid` Makes the table a **WITHOUT ROWID** one. Requires
  a primary key. Ignored if the table already exists.
* `--headers` If importing into an existing table, this option assumes
  the first line is a header with column/field names that should not
  be inserted. Default behavior mimics the sqlite3 shell and tries to
  insert all rows. When reading headers, they're used as column names
  for inserting rows, so the order of columns in the table can be
  different from the order in the CSV file.
* `--columns=COLUMNS` A comma-separted list of column names. When
  creating a table, normally the first line is used to get the column
  names. With this option, the given names are used instead, and the
  first line is treated as data (Unless `--headers` is also given;
  then the names must be the same but the order can be different).
* `--guess-types` Normally, all fields are inserted as strings. With
  this option, it tries to insert values that look like numbers as
  numbers.
* `--empty-nulls` Normally an empty field is treated as a 0 length
  string. This inserts them as `NULL`s instead.
* `--strip` When set, strips leading and trailing whitespace from
  fields (Such spaces are always kept if inside quoted fields. Spaces
  before or after the quotes are removed with this option).
* `--ignore` Ignore attempts to insert rows with constraint violations
  instead of aborting.
* `--replace` Replace an existing row with the current one on a
  constraint violation. Cannot be combined with `--ignore`.
* `--unsafe` Turn on options that speed up insertion at the cost of
  possible database corruption on OS crash or power loss.
* `--help` I need somebody! Not just anybody!

table2sql
---------

Convert a typical ASCII art table where columns are separated by pipes
(`|`) into SQLite DDL statements. The first line of the input is used
as the header to get column names.

Created as a way to make it easier to work with sample data in Stack
Overflow questions; hence none of the fine-tuning options for defining
keys, etc. like with `csv2sqlite`. It's intended mostly for use with
throwaway data and in-memory databases. Depends on [Regexp::Common].

### Usage ###

    table2sql [OPTIONS] [TABLE NAME] [TABLE FILE]
    
### Options ###

* `-t` Create a temporary table.
* `--help` Display help.

### Example ###

    $ table2sql example <<EOF
    Header1 | Header2
    --------+--------
      a     |    b
      1     |    2
    EOF
    BEGIN TRANSACTION;
    CREATE TABLE IF NOT EXISTS "example"("Header1","Header2");
    INSERT INTO "example" VALUES ('a','b');
    INSERT INTO "example" VALUES (1,2);
    COMMIT;


[DBD::SQLite]: https://metacpan.org/pod/DBD::SQLite
[CSV import]: https://www.sqlite.org/cli.html#csv_import
[Text::CSV_XS]: https://metacpan.org/pod/Text::CSV_XS
[Regexp::Common]: https://metacpan.org/pod/Regexp::Common
