% tpm2_nvcertify(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvcertify**(1) - Provides attestation of the contents of an NV index.

# SYNOPSIS

**tpm2_nvcertify** [*OPTIONS*] [*ARGUMENTS*]

# DESCRIPTION

**tpm2_nvcertify**(1) - Provides attestation of the contents of an NV index.
NOTE: As part of the attestation output, the NV index contents are revealed.

# OPTIONS

These options control the certification:

  * **-C**, **\--signingkey-context**=_OBJECT_:

    The key object that signs the attestation structure.

  * **-P**, **\--signingkey-auth**=_AUTH_:

    The authorization value provided for the object specified with -C.

  * **-c**, **\--nvauthobj-context**=_OBJECT_:

    The object that is the authorization handle for the NV object. It is either
    the NV index handle itself or the platform/ owner hierarchy handle. If not
    specified it defaults to the NV index handle.

  * **-p**, **\--nvauthobj-auth**=_AUTH_:

    The authorization value provided for the object specified with -c.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm to use in signature generation.

  * **-s**, **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the attestation data.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file.

  * **-o**, **\--signature**=_FILE_:

    Output file name for the signature data.

  * **-q**, **\--qualification**=_FILE\_OR\_HEX\_STR_:

    Optional, the policy qualifier data that the signer can choose to include in the
    signature. Can be either a hex string or path.

  * **\--size**=_NATURAL_NUMBER_:

    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * **\--offset**=_NATURAL_NUMBER_:

    The offset within the NV index to start reading from.

  * **--attestation**=_FILE_:

    The attestation data of the type TPM2_CREATION_INFO signed with signing key.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash unless rphash is
    also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

  * **-n**, **\--name**=_FILE_:

    The name of the NV index that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

  * **\-signer-name**=_FILE_:

    The name of the signing key that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

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
tpm2_nvdefine -s 32 -a "authread|authwrite" 1

dd if=/dev/urandom bs=1 count=32 status=none| \
tpm2_nvwrite 1 -i-

tpm2_createprimary -C o -c primary.ctx -Q

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx -c signing_key.ctx -Q

tpm2_readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q

tpm2_nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1
```

[returns](common/returns.md)

[footer](common/footer.md)
