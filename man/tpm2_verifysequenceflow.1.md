% tpm2_verifysequence(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_verifysequence**(1) - Verify a signature over a message using a TPM
verification sequence.

# SYNOPSIS

**tpm2_verifysequence** [*OPTIONS*]

# DESCRIPTION

**tpm2_verifysequence**(1) - This command verifies a signature over a message 
using the TPM sequence verification flow built from : 
- **TPM2_VerifySequenceStart()**
- **TPM2_SequenceUpdate()**
- **TPM2_VerifySequenceComplete()**

This command is intended for verifying signatures over message data.


# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Reference to the key used to start and complete the verification sequence.

  * **-p**, **\--sequence-auth**=_AUTH_:

    Authorization for the sequence.

  * **-i**, **\--input**=_FILE_:
  
    Input file containing the message whose signature is to be verified.
   
  * **-s**, **\--signature**=_FILE_:
  
    Input file containing the signature to verify.
    
  * **-t**, **\--ticket**=_FILE_:
  
    The validation file. 
    
  * **-h**, **\--hint**=_FILE_:
  
    Additional information from the signature to be verified.
    
  * **-C**, **\--context**=_OBJECT_:
  
    Additional context
    

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
tpm2 createprimary -C o -G mldsa87 -g sha256 -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
```

Step 2 is to sign.

```bash
tpm2_signsequenceflow -c signkey.ctx -i msg.bin -s signature.bin
```
Step 2 is to save the public part of the key for the verify.

```bash
tpm2_readpublic -c signkey.ctx -o signpub.out
```

Step 3 is to load the public part of the key.

```bash
tpm2_loadexternal -u signpub.out -c verifypub.ctx
```

Step 4 is to verified the signature

```bash
tpm2_verifysequenceflow -c verifypub.ctx -i msg.bin -s signature.bin -t verified.ticket
```

[returns](common/returns.md)

[footer](common/footer.md)
