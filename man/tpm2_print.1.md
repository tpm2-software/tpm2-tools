% tpm2_print(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_print**(1) - Prints TPM data structures

# SYNOPSIS

**tpm2_print** [*OPTIONS*] _PATH_

# DESCRIPTION

**tpm2_print**(1) - Decodes a TPM data structure and prints enclosed
elements to stdout as YAML. A file path containing a TPM object may
be specified as the _PATH_ argument. Reads from stdin if unspecified.

# OPTIONS

  * **-t**, **\--type**:

    Required. Type of data structure. Only **TPMS_ATTEST** and **TPMS_CONTEXT** are
    presently supported.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES


## Print a TPM Quote

### Setup a key to generate a qoute from
```bash
tpm2_createprimary -C e -c primary.ctx
tpm2_create -C primary.ctx -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
tpm2_quote -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18 -g sha256 -m msg.dat
```

### Print a Quote

```bash
tpm2_print -t TPMS_ATTEST msg.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
