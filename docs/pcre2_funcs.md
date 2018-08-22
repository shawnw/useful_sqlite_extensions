% PCRE2 regular expression functions

Introduction
============

This Sqlite3 extension module provides MySQL inspired regular
expression functions using the [PCRE2] engine. Every plain function is
also present with **PCRE_** prepended to the name, so multiple modules
that provide RE functions can coexist portably. (See the
`string_funcs` module for versions using [ICU] regular expressions.)
The default names are used by whichever module was loaded last.

[PCRE2]: https://www.pcre.org
[ICU]: http://site.icu-project.org

Functions
=========

Matching
--------

### REGEXP()

* REGEXP(re, string)
* string REGEXP re

Returns 1 if `string` matches against `re`. The entire string must match.

Informational
-------------

### PCRE_VERSION()

Returns the version of PCRE2 being used.

### PCRE_UNICODE_VERSION()

Returns the version of Unicode that PCRE2 is using.

To-Do
=====

* Add the rest of the functions.
