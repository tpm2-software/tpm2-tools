% tpm2_sign(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_sign**(1) - Sign a hash using the TPM.

# SYNOPSIS

**tpm2_sign** [*OPTIONS*]

# DESCRIPTION

**tpm2_sign**(1) - Signs an externally provided hash with the specified symmetric or
asymmetric signing key. If keyHandle references a restricted signing key, then
validation shall be provided, indicating that the TPM performed the hash of the
data and validation shall indicate that hashed data did not start with
**TPM_GENERATED_VALUE**. The scheme of keyHandle should not be **TPM_ALG_NULL**.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Context object pointing to the the key used for signing. Either a file or a
    handle number. See section "Context Object Format".

  * **-p**, **\--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-g**, **\--halg**=_HASH\_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-s**, **\--sig-scheme**=_SIGNING\_SCHEME_:

    The signing scheme used to sign the message. Optional.
    Signing schemes should follow the "formatting standards", see section
     "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported
     signature schemes.
    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
     be used.

  * **-m**, **\--message**=_MSG\_FILE_:

    The message file, containing the content to be  digested.

  * **-D**, **\--digest**=_DIGEST\_FILE_:

    The digest file that shall be computed using the correct hash
    algorithm. When this option is specified, a warning is generated and
    **both the message file (-m) and the validation ticket (-t) are
    ignored**.
    You cannot use this option to sign a digest against a restricted
    signing key.

  * **-t**, **\--ticket**=_TICKET\_FILE_:

    The ticket file, containing the validation structure, optional.

  * **-o**, **\--out-sig**=_SIGNATURE\_FILE_:

    The signature file, records the signature structure.

  * **-f**, **\--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[supported signing schemes](common/sign-alg.md)

[algorithm specifiers](common/alg.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

## Sign and verify with the TPM using the *endorsement* hierarchy
```
tpm2_createprimary -a e -o primary.ctx

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx

tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -o rsa.ctx

echo "my message > message.dat

tpm2_sign -c rsa.ctx -g sha256 -m message.dat -s sig.rssa

tpm2_verifysignature -c rsa.ctx -g sha256 -m message.dat -s sig.rssa
```

## Sign with the TPM and verify with OSSL
```
openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem

openssl ec -in private.ecc.pem -out public.ecc.pem -pubout

# Generate a hash to sign
echo "data to sign" > data.in.raw

sha256sum data.in.raw | awk '{ print "000000 " $1 }' | xxd -r -c 32 > data.in.digest

# Load the private key for signing
tpm2_loadexternal -Q -G ecc -r private.ecc.pem -o key.ctx

# Sign in the TPM and verify with OSSL
tpm2_sign -Q -c key.ctx -g sha256 -D data.in.digest -f plain -s data.out.signed

openssl dgst -verify public.ecc.pem -keyform pem -sha256 -signature data.out.signed data.in.raw
```

[returns](common/returns.md)

[footer](common/footer.md)
