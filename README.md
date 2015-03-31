SSS#
============

Implementation of Shamir's Secret Sharing Scheme in C#. Kind of crude.

It's basically a flat port of B. Poettering's [ssss version 0.5 (2005,2006)](http://point-at-infinity.org/ssss/) (GPL2)
This application makes use of Klaus Prückl's [Gnu.Getopt.NET](https://getopt.codeplex.com/) (LGPL2.1)

**_Currently this application does not work!_**
There appear to be bugs in [System.Numerics.BigInteger](https://msdn.microsoft.com/en-us/library/system.numerics.biginteger%28v=vs.110%29.aspx) and I'm not quite getting the conversions from the [GNU MP](https://gmplib.org/) implementation quite right, yet.
The application runs, but it will produce garbage, not work in reverse (combine) and/or be incompatible with the [original C implementation](http://sourcecodebrowser.com/ssss/0.5/ssss_8c.html).