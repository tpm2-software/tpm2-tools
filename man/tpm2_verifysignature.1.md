% tpm2_verifysignature(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_verifysignature**(1) - Validates a signature using the TPM.

# SYNOPSIS

**tpm2_verifysignature** [*OPTIONS*]

# DESCRIPTION

**tpm2_verifysignature**(1) - Uses loaded keys to validate a signature on a
message with the message digest passed to the TPM. If the signature check
succeeds, then the TPM will produce a **TPMT_TK_VERIFIED**. Otherwise, the TPM
shall return **TPM_RC_SIGNATURE**. If object references an asymmetric key, only
the public portion of the key needs to be loaded. If object references a
symmetric key, both the public and private portions need to be loaded.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Context object for the key context used for the operation. Either a file
    or a handle number. See section "Context Object Format".

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-m**, **\--message**=_FILE_:

    The message file, containing the content to be  digested.

  * **-d**, **\--digest**=_FILE_:

    The input hash file, containing the hash of the message. If this option is
    selected, then the message (**-m**) and algorithm (**-g**) options do not
    need to be specified.

  * **-s**, **\--signature**=_FILE_:

    The input signature file of the signature to be validated.

  * **-f**, **\--scheme**=_SCHEME_:

    The signing scheme that was used to sign the message. This option should only
    be specified if the signature comes in from a non *tss* standard, like openssl.
    See "Signature format specifiers" for more details. The *tss* format contains
    the signature metadata required to understand it's signature scheme.

    Signing schemes should follow the "formatting standards", see section
    "Algorithm Specifiers".

  * **\--format**=_SCHEME_:

    Deprecated. Same as **\--scheme**.

  * **-t**, **\--ticket**=_FILE_:

    The ticket file to record the validation structure.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

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

echo "my message > message.dat

tpm2_sign -c rsa.ctx -g sha256 -s sig.rssa message.dat

tpm2_verifysignature -c rsa.ctx -g sha256 -m message.dat -s sig.rssa
```

## Sign with openssl and verify with the TPM
```bash
# Generate an ECC key
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem

openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

# Generate a hash to sign (OSSL needs the hash of the message)
echo "data to sign" > data.in.raw

sha256sum data.in.raw | awk '{ print "000000 " $1 }' | \
xxd -r -c 32 > data.in.digest

# Load the private key for signing
tpm2_loadexternal -Q -G ecc -r private.ecc.pem -c key.ctx

# Sign in the TPM and verify with OSSL
tpm2_sign -Q -c key.ctx -g sha256 -d data.in.digest -f plain -s data.out.signed

openssl dgst -verify public.ecc.pem -keyform pem -sha256 \
-signature data.out.signed data.in.raw

# Sign with openssl and verify with TPM
openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw

tpm2_verifysignature -Q -c key.ctx -g sha256 -m data.in.raw -f ecdsa \
-s data.out.signed
```

[returns](common/returns.md)

[footer](common/footer.md)
