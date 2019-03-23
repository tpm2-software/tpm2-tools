% tpm2_verifysignature(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_verifysignature**(1) - Validates a signature using the TPM.

# SYNOPSIS

**tpm2_verifysignature** [*OPTIONS*]

# DESCRIPTION

**tpm2_verifysignature**(1) uses loaded keys to validate a signature on a message
with the message digest passed to the TPM. If the signature check succeeds,
then the TPM will produce a **TPMT_TK_VERIFIED**. Otherwise, the TPM shall return
**TPM_RC_SIGNATURE**. If _KEY\_HANDLE_ references an asymmetric key, only the
public portion of the key needs to be loaded. If _KEY\_HANDLE_ references a
symmetric key, both the public and private portions need to be loaded.

# OPTIONS

  * **-c**, **--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object for the key context used for the operation. Either a file
    or a handle number. See section "Context Object Format".

  * **-g**, **--halg**=_HASH\_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-m**, **--message**=_MSG\_FILE_:

    The message file, containing the content to be  digested.

  * **-D**, **--digest**=_DIGEST\_FILE_:

    The input hash file, containing the hash of the message. If this option is
    selected, then the message (**-m**) and algorithm (**-g**) options do not need
    to be specified.

  * **-s**, **--sig**=_SIG\_FILE_:

    The input signature file of the signature to be validated.

  * **-f**, **--format**:

    Set the input signature file to a specified format. The default is the tpm2.0 TPMT_SIGNATURE
    data format, however different schemes can be selected if the data came from an external
    source like OpenSSL. The tool currently only supports rsassa.

    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported hash
    algorithms.

  * **-t**, **--ticket**=_TICKET\_FILE_:

    The ticket file to record the validation structure.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[supported signing schemes](common/signschemes.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Sign and verify with the TPM using the *endorsement* hierarchy
```
tpm2_createprimary -a e -o primary.ctx
tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx
tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -o rsa.ctx

echo "my message > message.dat
tpm2_sign -c rsa.ctx -g sha256 -m message.dat -s sig.rssa
tpm2_verifysignature -c rsa.ctx -g sha256 -m message.dat -s sig.rssa
```

Sign with openssl and verify with the TPM
```
# Generate an ECC key
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem
openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

# Generate a hash to sign (OSSL needs the hash of the message)
echo "data to sign" > data.in.raw
sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest

# Load the private key for signing
tpm2_loadexternal -Q -G ecc -r private.ecc.pem -o key.ctx

# Sign in the TPM and verify with OSSL
tpm2_sign -Q -c key.ctx -g sha256 -D data.in.digest -f plain -s data.out.signed
openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw

# Sign with openssl and verify with TPM
openssl dgst -sha256 -sign private.ecc.pem -out data.out.signed data.in.raw
tpm2_verifysignature -Q -c key.ctx -g sha256 -m data.in.raw -f ecdsa -s data.out.signed
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
