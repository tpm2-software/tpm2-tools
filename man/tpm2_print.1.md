% tpm2_print(1) tpm2-tools | General Commands Manual
%
% DECEMBER 2017

# NAME

**tpm2_print**(1) - Prints TPM data structures

# SYNOPSIS

**tpm2_print** [*OPTIONS*]

# DESCRIPTION

**tpm2_print**(1) decodes a TPM data structure and prints enclosed
elements to stdout as YAML.

# OPTIONS

  * **-t**, **--type**:

    Required. Type of data structure. Only TPMS\_ATTEST and TPMS\_CONTEXT are
    presently supported.

  * **-f**, **--file**:

    Optional. File containing TPM object. Reads from stdin if unspecified.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_print -t TPMS_ATTEST -f /path/to/tpm/quote
tpm2_print --type=TPMS_ATTEST --file=/path/to/tpm/quote
cat /path/to/tpm/quote | tpm2_print --type=TPMS_ATTEST
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
