% POSIX regular expression functions

Introduction
============

This Sqlite3 extension module provides regular expression functions
using POSIX Extended and Basic syntax.

See the `string_funcs` module for versions using [ICU] regular
expressions and `pcre2_funcs` module for [PCRE2] regular expressions.

[PCRE2]: https://www.pcre.org
[ICU]: http://site.icu-project.org

Functions
=========

Matching
--------

### REGEXP()

* REGEXP(re, string)
* EXT_REGEXP(re, string)
* string REGEXP re

Returns 1 if `string` matches against the Extended Regular Expression `re`. 

### BASIC_REGEXP()

* BASIC_REGEXP(re, string)

Returns 1 if `string` matches against the Basic Regular Expression `re`.

To-Do
=====

* Add the rest of the MySQL RE functions.
