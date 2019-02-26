% Extra JSON functions

Introduction
============

This Sqlite3 extension adds some extra JSON handling functions to
supplement the standard [JSON1] extension. They're mostly inspired by
[MySQL JSON functions].

[JSON1]: https://www.sqlite.org/json1.html
[MySQL JSON functions]: https://dev.mysql.com/doc/refman/8.0/en/json-function-reference.html

Functions
=========

### JSON_EQUAL()

* JSON_EQUAL(json, json)

Returns 1 if the two JSON values are equivalent, 0 if not.

### JSON_LENGTH()

* JSON_LENGTH(json)
* JSON_LENGTH(json, path)

If `json` (Either the entire object, or the part of it at `path`) is
an object or array, return the number of elements in it. Otherwise,
returns 1.

### JSON_PRETTY()

* JSON_PRETTY(json)

Returns `json`, pretty-printed for human readability. The exact format
depends on the version of sqlite3 that the extension was compiled
against; 3.24 and newer produce MySQL style output, older produces
[cJSON] style.

[cJSON]: https://github.com/DaveGamble/cJSON

### JSON_KEYS()

* JSON_KEYS(json)
* JSON_KEYS(json, path)

Returns a JSON array of the keys of the given JSON object.

*** JSON_CONTAINS_PATH()

* JSON_CONTAINS_PATH(json, path)

Returns 1 if the json object has data at the given path, 0 otherwise.
