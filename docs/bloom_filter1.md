% Bloom Filter Virtual Table

Introduction
============

[Bloom filters] are a classic data structure for telling, in a fast
and compact manner, if a given value has a chance of being present in
a set. This extension module provides virtual tables that act as an
interface to a bloom filter. They can be useful as a fast index to
tell if a value is probably in a table or certainly isn't.

[Bloom filters]: https://en.wikipedia.org/wiki/Bloom_filter

Usage
=====

Creating a table
----------------

    CREATE VIRTUAL TABLE foo USING bloom_filter1(n, p, k);
    
The constructor takes three arguments:

* `n` -- the expected number of elements that will be stored in the filter.
* `p` -- the probability of false positives, as a number between 0 and
  1.0. The higher the number, the higher the chance of a false
  positive.
* `k` -- the number of times to hash each value into the filter.

The only mandatory one is `n`. If omitted, `p` defaults to **0.01**
(1%), and an ideal value of `k` is calculated.

Populating the table
--------------------

    INSERT INTO foo VALUES ('key 1'), ('key 2'), ...;

All values are first converted to `BLOB`s and the resuling bytes are
hashed. This means that integers and floating point numbers can
produce funny results. If you insert `1.0`, looking for `1` won't find
it, but looking for `'1.0'` will.

Querying the table
------------------

    SELECT * from foo('key 1');

Returns a single row with a single column set to **1** if the key is
found in the filter. No rows are returned if the key is not
present. This can be used with `EXISTS` and `IN` in queries.

I've thought about making `MATCH` work too, but it has some issues -
you can't have multiple modules loaded at once that use it, and syntax
would be ugly in its own way - you'd have to provide the table name as
a string.

Example
=======

    sqlite> CREATE TABLE plants(name);
    sqlite> CREATE VIRTUAL TABLE vegetables USING bloom_filter1(20);
    sqlite> INSERT INTO plants VALUES ('apple'), ('asparagus'), ('cabbage'), ('grass');
    sqlite> INSERT INTO vegetables VALUES ('asparagus'), ('cabbage');
    sqlite> SELECT * FROM plants WHERE EXISTS (SELECT * FROM vegetables(name));
    asparagus
    cabbage
    sqlite3> SELECT * FROM plants WHERE 1 NOT IN vegetables(name);
    apple
    grass
    
Implementation notes
====================

The underlying hash function is [SipHash].

For each virtual table `foo`, a backing table `foo_storage` is
created, with one row. It has a blob holding the bloom filter, and
some informational columns:

* `n` -- how many elements the table is intended for. The actual number
  of elements inserted into it is not tracked.
* `m` -- the number of bits used in the filter.
* `p` -- the false positive chance.
* `k` -- the number of hash functions used.

The Sqlite3 incremental blob API is used to avoid reading and writing
large amounts of data at once.

[SipHash]: https://en.wikipedia.org/wiki/SipHash
