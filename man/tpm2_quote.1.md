% tpm2_quote(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_quote**(1) - Provide a quote and signature from the TPM.

# SYNOPSIS

**tpm2_quote** [*OPTIONS*]

# DESCRIPTION

**tpm2_quote**(1) - Provide quote and signature for given list of PCRs in given
algorithm/banks.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Context object for the quote signing key.

  * **-p**, **\--auth**=_AUTH_:

    Specifies the authorization value for AK specified by option **-C**.

  * **-l**, **\--pcr-list**=_PCR_:

    The list of PCR banks and selected PCRs' ids for each bank.
    Also see **NOTES** section below.

  * **-m**, **\--message**=_FILE_:

    Message output file, records the quote message that makes up the data that
    is signed by the TPM.

  * **-s**, **\--signature**=_FILE_:

    Signature output file, records the signature in the format specified via the
    **-f** option.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file.

  * **-o**, **\--pcr**=_FILE_.

    PCR output file, optional, records the list of PCR values as defined
    by **-l**.

[PCR output file format specifiers](common/pcrs_format.md)
    Default is 'serialized'.

  * **-q**, **\--qualification**=_HEX\_STRING\_OR\_PATH_:

    Data given as a Hex string or binary file to qualify the quote, optional.
    This is typically used to add a nonce against replay attacks.

  * **-g**, **\--hash-algorithm**:

    Hash algorithm for signature. Defaults to sha256.

  * **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the message. Optional.
    Signing schemes should follow the "formatting standards", see section
     "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported
     signature schemes.
    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
     be used.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[signature format specifiers](common/signature.md) option used to configure
signature _FORMAT_.

[pcr bank specifiers](common/pcr.md) details the syntax for specifying pcr list.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_createprimary -C e -c primary.ctx

tpm2_create -C primary.ctx -u key.pub -r key.priv

tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx

tpm2_quote -Q -c key.ctx -l 0x0004:16,17,18+0x000b:16,17,18
```

# NOTES

The maximum number of PCR that can be quoted at once is associated
with the maximum length of a bank.

On most TPMs, it means that this tool can quote up to 24 PCRs
at once.

That this performs a detached signature.

[returns](common/returns.md)

[footer](common/footer.md)
