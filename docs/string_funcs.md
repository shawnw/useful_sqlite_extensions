% Extra Unicode Functions

Extra Unicode functions
=======================

This Sqlite3 extension module is an extension to the standard
[ICU extension] that adds extra functionality for dealing with text in
SQL queries.

Since the ICU extension itself doesn't seem to be compiled into or
otherwise provided by many OS's sqlite3 packages, it is included as
part of this one. See the Sqlite3 ICU documentation for details
about what it provides.

If you do a lot of things in your queries with Unicode text, or even
just use Unicode-aware collations on index columns, consider setting
the encoding of your databases to UTF-16 when creating them. Most [ICU]
functions work on UTF-16 strings, so this reduces the amount of
converting to and from UTF-8.

[ICU]: http://site.icu-project.org/
[ICU extension]: https://www.sqlite.org/src/dir?ci=cdb68d2c64e453fd&name=ext/icu

Scalar Functions
================

Informative
-----------

### ICU_VERSION

* ICU\_VERSION()

Returns the version of the ICU library being used.

### UNICODE_VERSION

* UNICODE_VERSION()

Returns the version of Unicode understood by ICU.

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

Normalization
-------------

Functions for normalizing Unicode text, and concatentation (Since
naive concatenation of two normalized Unicode strings can produce a
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

### NFD()

* NFD(string, ...)
* NFD_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the result in
NFD. With one argument is equivalent to `NORMALIZE(string, 'NFD')`.

### NFKC()

* NFKC(string, ...)
* NFKC_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the result in
NFKC. With one argument is equivalent to `NORMALIZE(string, 'NFKC')`.

### NFKD()

* NFKD(string, ...)
* NFKD_WS(sep, string, ...)

Concatenates its non-NULL arguments together and returns the reuslt in
NFKD. With one argument is equivalent to `NORMALIZE(string, 'NFKD')`.

Other conversions
-----------------

### TO_ASCII()

* TO_ASCII(string)

An enhanced version of `SPELLFIX1_TRANSLIT()` from the *spellfix1*
extension. It converts Unicode text to ASCII, trying to gracefully
downgrade accented characters, ligatures, smart quotes, smart dashes,
etc. It knows about more conversions than its inspiration, can handle
characters outside the BMP, and deals with grapheme clusters in a more
intelligent way.

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
* *l* means to treat the regexp as a literal string to search for.

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
difference when comparing UTF-16 text with code points outside the
BMP.

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

