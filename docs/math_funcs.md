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

Trigonometric
-------------

* ACOS(d)
* ACOSH(d)
* ASIN(d)
* ASINH(d)
* ATAN(d)
* ATAN2(d,d)
* ATANH(d)
* COS(d)
* COSH(d)
* COT(d) -- Cotangent
* SIN(d)
* SINH(d)
* TAN(d)
* TANH(d)
* DEGREES(d) -- Radians to degrees 
* RADIANS(d) -- Degrees to radians

Roots, Powers and Logs
----------------------

* CBRT(d) -- $\sqrt[3]{x}$
* EXP(d) -- $e^{x}$
* EXP2(d) -- $2^{x}$
* EXPM1(d) -- $e^{x-1}$
* HYPOT(d, d) -- $\sqrt{x^{2} + y^{2}}$
* LN(d) -- $\log_{e} x$
* LOG(d) -- Base ℯ like MySQL, not base 10 like Postgresql.
* LOG(d,d) -- $\log_{x} y$
* LOG1P(d) -- $\log_{e} (x+1)$
* LOG10(d) -- $\log_{10} x$
* LOG2(d) -- $\log_{2} x$
* POWER(d,d) -- $x^{y}$
* SQRT(d) -- $\sqrt{x}$

Rounding
--------

* CEIL(d)
* FLOOR(d)
* ROUND(d) -- Overrides the standard one-argument `ROUND()`. Rounds
  halfway cases away from zero.
* TRUNC(d) -- Rounds towards zero.

Math
----

* DIV(i, i) -- Integer division
* MOD(i, i) -- Integer remainder
* SIGN(d/i)
* PI() -- π

Other
-----

* BIT_COUNT(i) -- Returns the number of set bits in its integer argument.

Aggregate Functions
===================

Bitwise
-------

* BIT_OR(i)
* BIT_XOR(i)
* BIT_AND(i)

Statistics
----------

* COVAR_POP(d, d)
* COVAR_SAMP(d, d)
* STDDEV_POP(d)
* STDDEV_SAMP(d)
* VAR_POP(d)
* VAR_SAMP(d)
