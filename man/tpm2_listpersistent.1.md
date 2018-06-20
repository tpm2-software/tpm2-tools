% tpm2_listpersistent(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_listpersistent**(1) - Display all defined persistent objects.

# SYNOPSIS

**tpm2_listpersistent** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_listpersistent**(1) - display all defined persistent objects.

# OPTIONS

These options for listing the persistent objects:

  * **-g**, **--halg**=_ALGORITHM_:
    Only display persistent objects using this hash algorithm. Algorithms should
    follow the "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-G**, **--kalg**=_KEY\_ALGORITHM_:
    Only display persistent objects using this key algorithm.
    See section "Supported Public Object Algorithms"
    for a list of supported object algorithms.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

```
tpm2_listpersistent
tpm2_listpersistent -g sha256 -G ecc

```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
