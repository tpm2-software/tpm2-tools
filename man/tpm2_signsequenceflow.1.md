% tpm2_signsequence(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_signsequence**(1) - Sign a message using a TPM signature sequence.

# SYNOPSIS

**tpm2_signsequence** [*OPTIONS*]

# DESCRIPTION

**tpm2_signsequence**(1) - This command signs a message using the TPM sequence signing 
flow built from : 
- **TPM2_SignSequenceStart()**
- **TPM2_SequenceUpdate()**
- **TPM2_SignSequenceComplete()**

This command is intended for signing message data.


# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Reference to the signing key used to start and complete the sign sequence.

  * **-P**, **\--key-auth**=_AUTH_:

    The authorization value for the signing key.

  * **-i**, **\--input**=_FILE_:
  
    Input file containing the message to sign.
    
  * **-p**, **\--sequence-auth**=_AUTH_:
  
    The authorization value for the sequence.
    
  * **-s**, **\--signature**=_FILE_:
  
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
tpm2 createprimary -C o -G mldsa87 -g sha256 -c signkey.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign'
```

Step 2 is to sign.

```bash
tpm2_signsequenceflow -c signkey.ctx -i msg.bin -s signature.bin
```
Step 3 is to save the public part of the key for the verify.

```bash
tpm2_readpublic -c signkey.ctx -o signpub.out
```


[returns](common/returns.md)

[footer](common/footer.md)
