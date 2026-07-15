% tpm2_decapsulate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_decapsulate**(1) - Perform a KEM decapsulation with a private TPM key.

# SYNOPSIS

**tpm2_decapsulate** [*OPTIONS*]

# DESCRIPTION

**tpm2_decapsulate**(1) - This command performs the private key operation of a 
Key Encapsulation Mechanism (KEM) using a TPM private key.

Given a private key and a ciphertext produced by an earlier encapsulation operation
such as **TPM2_Encapsulate()**, the command returns the same **sharedSecret** that
was produced during encapsulation. 


# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    Reference to the loaded KEM key to use for decapsulation.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the key.

  * **-i**, **\--ciphertext**=_FILE_:
  
	Input file path containing the encapsulated ciphertext.
	
  * **-s**, **\--shared-secret**=_FILE_:
  
	Output file path for the decaspsulated shared secret


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
The first step is to create the primary object with mlkem.

```bash
tpm2 createprimary -C o -G mlkem1024 -g sha256 -c mlkem.ctx -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt'
```

Step 2 is to encapsulate.

```bash
tpm2_encapsulate -c mlkem.ctx --shared-secret=secret.bin --ciphertext=ciphertext.bin
```

Step 3 is to decapsulate.

```bash
tpm2_decapsulate -c mlkem.ctx --ciphertext=ciphertext.bin --shared-secret=secret_dec.bin
```

[returns](common/returns.md)

[footer](common/footer.md)
