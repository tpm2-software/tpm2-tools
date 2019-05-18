% tpm2_print(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_print**(1) - Prints TPM data structures

# SYNOPSIS

**tpm2_print** [*OPTIONS*]

# DESCRIPTION

**tpm2_print**(1) - Decodes a TPM data structure and prints enclosed
elements to stdout as YAML.

# OPTIONS

  * **-t**, **\--type**:

    Required. Type of data structure. Only **TPMS_ATTEST** and **TPMS_CONTEXT** are
    presently supported.

  * **-i**, **\--in-file**:

    Optional. File containing TPM object. Reads from stdin if unspecified.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_print -t TPMS_ATTEST -f /path/to/tpm/quote

tpm2_print \--type=TPMS_ATTEST \--file=/path/to/tpm/quote

cat /path/to/tpm/quote | tpm2_print \--type=TPMS_ATTEST
```

[returns](common/returns.md)

[footer](common/footer.md)
