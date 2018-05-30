% Extra String Functions

Introduction
============

This Sqlite3 extension module adds extra functionality for dealing
with text in SQL queries, with an emphasis on Unicode. It depends on
[ICU] for most of its features.

Since the standard [ICU extension] itself doesn't seem to be compiled
into or otherwise provided by many OS's sqlite3 packages, it is
included as part of this one. See that documentation for details about
what it provides.

If you do a lot of things in your queries with Unicode text, or even
just use Unicode-aware collations on index columns, consider setting
the encoding of your databases to UTF-16 when creating them. Most
[ICU] functions work on UTF-16 strings, so this reduces the amount of
converting to and from UTF-8.

[ICU]: http://site.icu-project.org/
[ICU extension]: https://www.sqlite.org/src/dir?ci=cdb68d2c64e453fd&name=ext/icu

Scalar Functions
================

Informative
-----------

### ICU_VERSION()

* ICU_VERSION()

Returns the version of the ICU library being used.

### UNICODE_VERSION()

* UNICODE_VERSION()

Returns the version of Unicode understood by ICU.

### CHAR_NAME()

* CHAR_NAME(c)

Returns the Unicode name of the first codepoint in `c`.

### GCLENGTH()

* GCLENGTH(string)

Returns the number of [extended grapheme clusters] in `string`. This
will be less than or equal to `LENGTH(string)`, which returns the
number of *code points*.

[extended grapheme clusters]: http://unicode.org/reports/tr29/#Grapheme_Cluster_Boundaries

Case Mapping
------------

### UPPER()

* UPPER(string)
* UPPER(string, locale)

Returns `string` converted to uppercase, with an optional `locale` for
specific rules.

### LOWER()

* LOWER(string)
* LOWER(string, locale)

Returns `string` converted to lowercase, with an optional `locale` for
specific rules.

### TITLE()

* TITLE(string)
* TITLE(string, locale)
* INITCAP(string)

Returns `string` converted to lowercase, and the first letter of each
word titlecased. The optional `locale` argument uses specific casing
rules, like with `UPPER()` and `LOWER()`.

If `string` is `NULL`, returns `NULL`.

### CASEFOLD()

* CASEFOLD(string)

Returns a case-folded version of `string`.

If `string` is `NULL`, returns `NULL`.

Text Extraction
---------------

Sqlite3 provides one function, `SUBSTR()`, for extracting text from a
string. It has the major drawback that it treats one Unicode code
point as one character. As soon as you start getting outside of the
Latin characters (And even in them if dealing with text in NFD
format), that's not true. It's very easy to cut off a base character's
following combining characters, for example, with undesirable results.

The entire question of "What is a character?" gets very complicated
fast when it comes to Unicode. The following functions consider
characters to be [extended grapheme clusters], which means they
*usually* do what people expect.

### GCLEFT()

* GCLEFT(string, len)

Returns the first `len` [extended grapheme clusters] from `string`.

If `len` is negative, returns all but the last `abs(len)` clusters.

### GCRIGHT()

* GCRIGHT(string, len)

Returns the last `len` [extended grapheme clusters] from `string`.

If `len` is negative, returns all but the first `abs(len)` clusters.

### GCSUBSTR()

* GCSUBSTR(string, start, len)
* GCSUBSTR(string, start)

The `GCSUBSTR(string, start, len)` function returns a substring of
input `string` that begins with the `start`-th extended grapheme
cluster and which is `len` clusters long. If `len` is omitted then
`GCSUBSTR(string, start)` returns all clusters through the end of the
string beginning with the `start`-th. The left-most cluster of
`string` is number 1.

Normalization
-------------

Functions for normalizing Unicode text, and normalized concatentation
(Since naive joining of two normalized Unicode strings can produce a
non-normalized string. Yay Unicode!).

To-Do: Aggregate versions?

### NORMALIZE()

* NORMALIZE(string, form)

Returns `string` normalized according to `form`, which can be one of
`'NFC'`, `'NFD'`, `'NFKC'`, `'NFKD'`, or `'NFKCCaseFold'`.

If `string` is `NULL`, returns `NULL`.

### NFC()

* NFC(string, ...)
* NFC_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the result in
NFC. With one argument is equivalent to `NORMALIZE(string, 'NFC')`.

The `_WS` version intersperses `sep` between strings.

### NFD()

* NFD(string, ...)
* NFD_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the result in
NFD. With one argument is equivalent to `NORMALIZE(string, 'NFD')`.

The `_WS` version intersperses `sep` between strings.

### NFKC()

* NFKC(string, ...)
* NFKC_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the result in
NFKC. With one argument is equivalent to `NORMALIZE(string, 'NFKC')`.

The `_WS` version intersperses `sep` between strings.

### NFKD()

* NFKD(string, ...)
* NFKD_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the reuslt in
NFKD. With one argument is equivalent to `NORMALIZE(string, 'NFKD')`.

The `_WS` version intersperses `sep` between strings.

Other conversions
-----------------

### TO_ASCII()

* TO_ASCII(string)

An enhanced version of `SPELLFIX1_TRANSLIT()` from the *spellfix1*
extension. It converts Unicode text to ASCII, trying to gracefully
downgrade many Latin accented characters and ligatures, transliterate
Greek and Cyrillic characters, smart quotes, smart dashes, etc. It
knows about more conversions than its inspiration, can handle
characters outside the BMP, and deals with combining characters in a
more intelligent way.

Unicode Text Compression
------------------------

There are a few Unicode-specific text compression algorithms. They
don't have as good a compression ratio as more general purpose ones,
but they have low overhead for compressing short strings. Could come
in handy if you have a table with many short to medium length strings
and are trying to save some space.

### SCSU_COMPRESS()

* SCSU_COMPRESS(string)

Returns a blob representing `string` compressed with [SCSU].

### SCSU_DECOMPRESS()

* SCSU_DECOMPRESS(blob)

Decompresses `blob`, which should be [SCSU] compressed Unicode text.

### BOCU_COMPRESS()

* BOCU_COMPRESS(string)

Returns a blob representing `string` compressed with [BOCU-1].

### BOCU_DECOMPRESS()

* BOCU_DECOMPRESS(blob)

Decompresses `blob`, which should be [BOCU-1] compressed Unicode text.

[SCSU]: https://en.wikipedia.org/wiki/Standard_Compression_Scheme_for_Unicode
[BOCU-1]: https://en.wikipedia.org/wiki/Binary_Ordered_Compression_for_Unicode

Regular Expressions
-------------------

MySQL-compatible regular expression functions. All also work when the
name is prefixed by **ICU\_**, to support coexisting with future
extensions that use different engines - PCRE, RE2, etc. being loaded
at the same time.

The `match_type` string argument supports some extra options over MySQL:

* *w* means to use Unicode word breaks instead of traditional ones.
* *x* means that the regexp can have comments and whitespace.
* *l* means to treat the regexp as a literal string to search for and
  not a regular expression.

### REGEXP()

* REGEXP(re, string)
* REGEXP(re, string, match_type)
* string REGEXP re

Returns 1 if `string` matches `re`. The entire string must match. The
three argument version is an extension over the normal ICU extension
implementation.

### REGEXP_INSTR()

See [MySQL REGEXP_INSTR()] documentation.

If the `match_type` option has a digit in the range 0-9 in it, the
position of that capturing group is returned instead of the complete
match. 0 is the full match.

[MySQL REGEXP_INSTR()]: https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-instr

### REGEXP_LIKE()

See [MySQL REGEXP_LIKE()] documentation.

[MySQL REGEXP_LIKE()]: https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-like

### REGEXP_REPLACE()

See [MySQL REGEXP_REPLACE()] documentation.

This implementation currently only supports a `pos` argument of 1 and
`occurence` of 0 or 1. It also replaces tokens like `$N` in the
replacement string with the N-th capture group.

[MySQL REGEXP_REPLACE()]: https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-replace

### REGEXP_SUBSTR()

See [MySQL REGEXP_SUBSTR()] documentation.

If the `match_type` option has a digit in the range 0-9 in it, that
capturing group is returned instead of the complete match. 0 is the
full match.

[MySQL REGEXP_SUBSTR()]: https://dev.mysql.com/doc/refman/8.0/en/regexp.html#function_regexp-substr

Other functions
---------------

### CONCAT()

* CONCAT(string, ...)
* MYSQL_CONCAT(string, ...)
* CONCAT_WS(sep, string, ...)

Returns a string concatenating its arguments together. If
`MYSQL_CONCAT()` gest a `NULL` argument, it returns `NULL`. The other
versions just skip those arguments. The `_WS` version puts `sep`
between strings.

Collations
==========

For when `BINARY` and `NOCASE` aren't good enough.

Functions
---------

### ICU_LOAD_COLLATION(locale, name)

See the [ICU extension] documentation.

Predefined collation types
--------------------------

### CODEPOINT

Compares code points instead of code units like `BINARY` does. Makes a
difference when comparing UTF-16 text with surrogate pairs.

### UNOCASE

Unicode-aware case-insensitive ordering. Compares case-folded code
points without any locale-specific rules. If doing lots of
comparisions, it's better to use precomputed casefolded strings.

### EQUIV

Unicode equivalence. The same string normalized in two
different forms is equivalent. If comparing a lot of strings, it's
best to canonize them with the same normalization form.

### ENOCASE

Case-insensitive Unicode equivalence. If comparing a lot of strings,
it's better to use precomputed case folded and normalized ones.

Examples
--------

    char(0x0122) = char(0x0123) COLLATE BINARY       => 0
    char(0x0122) = char(0x0123) COLLATE NOCASE       => 0
    char(0x0122) = char(0x0123) COLLATE UNOCASE      => 1
    char(0x0122) = nfd(char(0x0122)) COLATE BINARY   => 0
    char(0x0122) = nfd(char(0x0122)) COLLATE EQUIV   => 1
    char(0x0122) = nfd(char(0x0123)) COLLATE EQUIV   => 0
    char(0x0122) = nfd(char(0x0123)) COLLATE ENOCASE => 1

