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

  * **-p**, **\--certifiedkey-auth**=_AUTH_:

    The authorization value provided for the object specified with -c.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm to use in signature generation.

  * **-P**, **\--signingkey-auth**=_AUTH_:

    The authorization value for the signing key specified with -C.

  * **-o**, **\--attestation**=_FILE_:

    Output file name for the attestation data.

  * **-s**, **\--signature**=_FILE_:

    Output file name for the signature data.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file.

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

```bash
tpm2_certify -H 0x81010002 -P 0x0011 -p 0x00FF -g 0x00B -a <fileName> \
-s <fileName>

tpm2_certify -C obj.context -c key.context -P 0x0011 -p 0x00FF -g 0x00B \
-a <fileName> -s <fileName>

tpm2_certify -H 0x81010002 -P 0011 -p 00FF  -g 0x00B -a <fileName> -s <fileName>
```

[returns](common/returns.md)

[footer](common/footer.md)
