% tpm2_certify(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_certify**(1) - Prove that an object is loaded in the TPM.

# SYNOPSIS

**tpm2_certify** [*OPTIONS*]

# DESCRIPTION

**tpm2_certify**(1) - Proves that an object with a specific _NAME_ is loaded in
the TPM. By certifying that the object is loaded, the TPM warrants that a public
area with a given _NAME_ is self-consistent and associated with a valid
sensitive area.

If a relying party has a public area that has the same _NAME_ as a _NAME_
certified with this command, then the values in that public area are correct.
An object that only has its public area loaded cannot be certified.

# OPTIONS

These options control the certification:

  * **-c**, **\--certifiedkey-context**=_OBJECT_:

    The object to be certified.

  * **-C**, **\--signingkey-context**=_OBJECT_:

    The key used to sign the attestation structure.

  * **-P**, **\--certifiedkey-auth**=_AUTH_:

    The authorization value provided for the object specified with -c.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm to use in signature generation.

  * **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the message. Optional.
    Signing schemes should follow the "formatting standards", see section
     "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported
     signature schemes.
    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
     be used.

  * **-p**, **\--signingkey-auth**=_AUTH_:

    The authorization value for the signing key specified with -C.

  * **-o**, **\--attestation**=_FILE_:

    Output file name for the attestation data.

  * **-s**, **\--signature**=_FILE_:

    Output file name for the signature data.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is
    also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[signature format specifiers](common/signature.md) option used to configure
signature _FORMAT_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

Create a primary key and certify it with a signing key.

```bash
tpm2_createprimary -Q -C e -g sha256 -G rsa -c primary.ctx

tpm2_create -Q -g sha256 -G rsa -u certify.pub -r certify.priv -C primary.ctx

tpm2_load -Q -C primary.ctx -u certify.pub -r certify.priv -n certify.name \
-c certify.ctx

tpm2_certify -Q -c primary.ctx -C certify.ctx -g sha256 -o attest.out -s sig.out
```

[returns](common/returns.md)

[footer](common/footer.md)
