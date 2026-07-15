% tpm2_verifydigestsignature(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_verifydigestsignature**(1) - Verify a signature over a message digest with a 
TPM key.

# SYNOPSIS

**tpm2_verifydigestsignature** [*OPTIONS*]

# DESCRIPTION

**tpm2_verifydigestsignature**(1) - This command verifies a signature over a 
precomputed digest using a TPM verification key.

The key referenced by **keyHandle** must use a signing scheme that supports 
signing a digest, such as **TPM_ALG_ECDSA**



**NOTE**: Unrestricted **ML-DSA** keys can only be used with **TPM2_SignDigest()**
if **allowExternalMu** is TRUE.

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Reference to the public key used for the signature verification.

  * **-g**, **\--context**=_FILE_:
  
    Optionnal additional verification context.
    
  * **-d**, **\--digest**=_FILE_:
  
    The digest whose signature is to be verified.
    
  * **-s**, **\--signature**=_FILE_:
  
    Input file containing the signature to verify.
    
  * **-t**, **\--validation**=_FILE_:
  
    Output file path for the returned validation ticket.
    
    On success, the ticket tag will be **TPM_ST_DIGEST_VERIFIED**.

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

Step 3 is to verify the signature.

```bash
tpm2 verifydigestsignature -c signkey.ctx -d digest.bin -s signature.bin -t validation.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
