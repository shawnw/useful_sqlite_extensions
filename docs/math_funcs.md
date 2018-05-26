% Math and Numeric Functions

Introduction
============

Mostly lifted from MySQL and Postgres. Unless otherwise documented,
they do the same thing as the C function of the same name. Pass them
`NULL`, get `NULL` back. Do something that would make them return a
`NaN`, get `NULL` back. In the arguments, *d* means a floating point
number, *i* means an integer. *d/i* means either.

Scalar Functions
================

Trigonmetric
------------

* ACOS(d)
* ASIN(d)
* ATAN(d)
* ATAN2(d,d)
* COS(d)
* COT(d) -- Cotangent
* SIN(d)
* TAN(d)
* DEGREES(d)
* RADIANS(d)

Roots, Powers and Logs
----------------------

* CBRT(d)
* EXP(d)
* LN(d)
* LOG(d) -- Base ℯ like MySQL, not base 10 like Postgresql.
* LOG(d,d)
* LOG10(d)
* LOG2(d)
* POWER(d,d)
* SQRT(d)

Rounding
--------

* CEIL(d)
* FLOOR(d)
* ROUND(d) -- Overrides the standard one-argument `ROUND()`. Rounds
  halfway cases away from zero.
* TRUNC(d) -- Rounds towards zero.

Math
----

* DIV(i, i)
* MOD(i, i)
* SIGN(d/i)
* PI() -- π

Aggregate Functions
===================

Bitwise
-------

* BIT_OR(i)
* BIT_XOR(i)
* BIT_AND(i)
