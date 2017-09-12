tpm2_pcrevent 1 "AUGUST 2017" tpm2-tools
==================================================

NAME
----

tpm2_akparse(1) - parses algorithm and key values from an ak output file generated via tpm2_getpubak(1).

SYNOPSIS
--------

`tpm2_akparse` [OPTIONS]

DESCRIPTION
-----------

tpm2_akparse(1) - parse the algorithm and key values in `TPM2B_PUBLIC` struct
which is input via file _INPUT\_FILE_ and the output key sent to _OUTPUT\_FILE_.

OPTIONS
-------

These options control parsing:

  * `-f`, `--file`=_INPUT_FILE_:
    The input file to parse. This file is output via tpm2_getpubak(1) via the -f option.

  * `-k`, `--key-file`=_OUTPUT_FILE_:
    The output file for the raw key value(s).

[common options](common/options.md)

[common tcti options](common/tcti.md)

EXAMPLES
--------

```
tpm2_akparse -f ak.data -k ak.key
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

## AUTHOR
William Roberts <william.c.roberts@intel.com>
