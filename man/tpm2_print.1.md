% tpm2_print(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_print**(1) - Prints TPM data structures

# SYNOPSIS

**tpm2_print** [*OPTIONS*] [*ARGUMENT* or *STDIN*]

# DESCRIPTION

**tpm2_print**(1) - Decodes a TPM data structure and prints enclosed elements
to stdout as YAML. A file path containing a TPM object or a TSS2 Private Key
in the PEM format may be specified as the path argument. Reads from stdin if
unspecified.

# OPTIONS

  * **-t**, **\--type**:

    Required. Type of data structure. The option supports the following arguments:
      * **TPMS_ATTEST**
      * **TPMS_CONTEXT**
      * **TPM2B_PUBLIC**
      * **TPMT_PUBLIC**
      * **TSSPRIVKEY_OBJ**
  * **ARGUMENT** the command line argument specifies the path of the TPM data.

[pubkey options](common/pubkey.md)

    Public key format. This only works if option `--type/-t` is set to
    TPM2B_PUBLIC or TPMT_PUBLIC.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

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

### Print a public file

```bash
tpm2_print -t TPM2B_PUBLIC key.pub
```

### Print a tpmt public file
```bash
tpm2_readpublic -c key.ctx -f tpmt -o key.tpmt
tpm2_print -t TPMT_PUBLIC key.tpmt
```

### Print a TPM2B_PUBLIC file and convert to PEM format

```bash
tpm2 print -t TPM2B_PUBLIC -f pem key.pub
```

### Print public portion of TSSPRIVKEY PEM file and convert to PEM format

```bash
tpm2 print -t TSSPRIVKEY_OBJ tssprivkey.pem
tpm2 print -t TSSPRIVKEY_OBJ tssprivkey.pem -f pem > publickey.pem
```

[returns](common/returns.md)

[footer](common/footer.md)
