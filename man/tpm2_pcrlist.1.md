% tpm2_pcrlist(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_pcrlist**(1) - List PCR values.

# SYNOPSIS

**tpm2_pcrlist** [*OPTIONS*]

# DESCRIPTION

**tpm2_pcrlist**(1) Displays PCR values. Without any options, **tpm2_pcrlist**
outputs all pcrs and their hash banks. One can use either the **-g** or **-L**
mutually exclusive options to filter the output.

# OPTIONS

  * **-f**, **--format**=_FORMAT_:
    Specify the output format. Valid output formats are:
    * yaml - output in the YAML file format.

  * **-g**, **--algorithm**=_HASH\_ALGORITHM_:
    Only output PCR banks with the given algorithm.
    Algorithms should follow the "formatting standards, see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-L**, **--sel-list**=_PCR\_SELECTION\_LIST_:

    The list of pcr banks and selected PCRs' ids for each bank to display.
    _PCR\_SELECTION\_LIST_ values should follow the
    pcr bank specifiers standards, see section "PCR Bank Specfiers".

  * **-s**, **--algs**:
    Output the list of supported algorithms.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[pcr bank specifiers](common/pcr.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

display all PCR values:

```
tpm2_pcrlist
```

Display the PCR values with a specified bank:

```
tpm2_pcrlist -g sha1
```

Display the PCR values with specified banks and store in a file:

```
tpm2_pcrlist -L sha1:16,17,18+sha256:16,17,18 -o pcrs
```

Display the supported PCR bank algorithms and exit:

```
tpm2_pcrlist -s
```

# RETURNS

0 on success or 1 on failure.

# BUGS

[Github Issues](https://github.com/01org/tpm2-tools/issues)

# HELP

See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)