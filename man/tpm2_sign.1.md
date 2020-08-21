% tpm2_sign(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_sign**(1) - Sign a hash or message using the TPM.

# SYNOPSIS

**tpm2_sign** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_sign**(1) - Generates signature of specified message or message-digest
using the specified symmetric or asymmetric signing key.

When signing a message, **tpm2_sign** utility first calculates the digest of the
message similar to the **tpm2_hash** command. It also generates a validation
ticket under TPM2_RH_NULL or TPM2_RH_OWNER hierarchies respectively for
unrestricted or the restricted signing keys.

While signing messages is a provision in this tool it is recommended to use the
**tpm2_hash** tool first and pass the digest and validation ticket.

NOTE: If the signing key is a restricted signing key, then validation and digest
must be provided via the **-t** input. The ticket indicates that the TPM performed the hash of the message.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Context object pointing to the the key used for signing. Either a file or a
    handle number. See section "Context Object Format".

  * **-p**, **\--auth**_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-s**, **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the message. Optional.

    Signing schemes should follow the "formatting standards", see section
    "Algorithm Specifiers".

    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
    be used.

  * **-d**, **\--digest**:

    Indicate that _FILE_ is a file containing the digest of the message.
    When this option and **-t** is specified, a warning is
    generated and the **validation ticket (-t) is ignored**.
    You cannot use this option to sign a digest against a restricted
    signing key.

  * **-t**, **\--ticket**=_FILE_:

    The ticket file, containing the validation structure, optional.

  * **-o**, **\--signature**=_FILE_:

    The signature file, records the signature structure.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file. See section
    "Signature Format Specifiers".

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **\--commit-index**=_NATURALNUMBER_

    The commit counter value to determine the key index to use in an ECDAA
    signing scheme. The default counter value is 0.

  * **ARGUMENT** the command line argument specifies the file data for sign.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

[signature format specifiers](common/signature.md)

# EXAMPLES

## Sign and verify with the TPM using the *endorsement* hierarchy
```bash
tpm2_createprimary -C e -c primary.ctx

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx

tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

echo "my message" > message.dat

tpm2_sign -c rsa.ctx -g sha256 -o sig.rssa message.dat

tpm2_verifysignature -c rsa.ctx -g sha256 -s sig.rssa -m message.dat
```

## Sign with the TPM and verify with OSSL
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem

openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

# Generate a hash to sign
echo "data to sign" > data.in.raw

sha256sum data.in.raw | awk '{ print "000000 " $1 }' | \
xxd -r -c 32 > data.in.digest

# Load the private key for signing
tpm2_loadexternal -Q -G ecc -r private.ecc.pem -c key.ctx

# Sign in the TPM and verify with OSSL
tpm2_sign -Q -c key.ctx -g sha256 -d -f plain -o data.out.signed data.in.digest

openssl dgst -verify public.ecc.pem -keyform pem -sha256 \
-signature data.out.signed data.in.raw
```

[returns](common/returns.md)

[footer](common/footer.md)
