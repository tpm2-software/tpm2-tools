% tpm2_signdigest(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_signdigest**(1) - Sign a message digest with a TPM signinkg key.

# SYNOPSIS

**tpm2_signdigest** [*OPTIONS*]

# DESCRIPTION

**tpm2_signdigest**(1) - This command signs a precomputed digest using a TPM 
signing key.

The key referenced by **keyHandle** must use a signing scheme that supports 
signing a digest, such as **TPM_ALG_ECDSA**.

The size of **digest** must match the size of the hash algorithm required by the
key signing scheme.

**NOTE**: Unrestricted **ML-DSA** keys can only be used with **TPM2_SignDigest()**
if **allowExternalMu** is TRUE.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Reference to the signing key that will perform the signature operation.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the signing key specified by **-c**.

  * **-g**, **\--context**=_FILE_:
  
    Optional additional signing context.
    
  * **-d**, **\--digest**=_FILE_:
  
    The digest to sign.
    
  * **-t**, **\--ticket**=_FILE_:
  
    Input file containing the **TPMT_TK_HASHCHECK** validation ticket.
    
  * **-o**, **\--signature**=_FILE_:
  
    Output file path for the generated signature.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Setup
The first step is to create the primary object with mldsa.

```bash
tpm2 createprimary -C o -G mldsa87 -g sha512 -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
```

Step 2 is to sign.

```bash
tpm2 signdigest -c signkey.ctx -d digest.bin -o signature.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
