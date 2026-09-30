% tpm2_encapsulate(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_encapsulate**(1) - Perform a KEM encapsulation with a public TPM key.

# SYNOPSIS

**tpm2_encapsulate** [*OPTIONS*]

# DESCRIPTION

**tpm2_encapsulate**(1) - This command performs the public key operation of a 
Key Encapsulation Mechanism (KEM) using the public portion of a TPM key.

Given a recipient public key referenced by **keyHandle**, the command produces : 
- a **shared secret**
- an associated **ciphertext**


# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    The public portion of the KEM key.

  * **-s**, **\--shared-secret**=_FILE_:

    Output file path for the generated shared secret.

  * **-t**, **\--ciphertext**=_FILE_:

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

[returns](common/returns.md)

[footer](common/footer.md)
