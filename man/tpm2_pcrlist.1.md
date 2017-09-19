tpm2_pcrlist 1 "AUGUST 2017" tpm2-tools
==================================================

NAME
----

tpm2_pcrlist(1) - List PCR values.

SYNOPSIS
--------

`tpm2_pcrlist` [OPTIONS]

DESCRIPTION
-----------

tpm2_pcrlist(1) Displays PCR values.

OPTIONS
-------

  * `-g`, `--algorithm`=_HASH\_ALGORITHM_:
    Only output PCR banks with the given algorithm.

  * `-L`, `--selList`=_PCR\_SELECTION\_LIST_:
    Only output the following PCRs ids. (0~23) for each bank.

  * `-s`, `--algs`:
    Output the list of supported algorithms.

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

display all PCR values:

```
tpm2_pcrlist
```

Display the PCR values with a specified bank:

```
tpm2_pcrlist -g 0x04
```

Display the PCR values with specified banks and store in a file:

```
tpm2_pcrlist -L 0x04:16,17,18+0x0b:16,17,18 -o pcrs
```

Display the supported PCR bank algorithms and exit:

```
tpm2_pcrlist -s
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)