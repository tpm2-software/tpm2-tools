% tpm2_createek(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_createek**(1) - Generate TCG profile compliant endorsement key.

# SYNOPSIS

**tpm2_createek** [*OPTIONS*]

# DESCRIPTION

**tpm2_createek**(1) - Generate TCG profile compliant endorsement key (EK),
which is the primary object of the endorsement hierarchy.

If a transient object is generated the tool outputs a context file specified
with **-c**.

Refer to:
<http://www.trustedcomputinggroup.org/files/static_page_files/7CAA5687-1A4B-B294-D04080D058E86C5F>

# OPTIONS

  * **-P**, **\--eh-auth**=_AUTH_:

    The authorization value for the endorsement hierarchy

  * **-w**, **\--owner-auth**=_AUTH_

    The authorization value for the owner hierarchy.

  * **-c**, **\--ek-context**=_OBJECT_ or _FILE_:

    Either a file path or a persistent handle value to save the endorsement key.

    If a value of **-** is passed the tool will find a vacant persistent handle
    to use and print out the automatically selected handle.

    If one saves the context file via this option and the public key via the
    **-u** option, the EK can be restored via a call to **tpm2_loadexternal**(1).

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The endorsement key algorithm. Supports:
    * **ecc** - A NIST_P256 key by default. Alternative curves can be selected
      using algorithm specifiers (e.g. **ecc384** or **ecc_nist_p384**) .
    * **rsa** - An RSA2048 key.
    * **keyedhash** - hmac key.

  * **-u**, **\--public**=_FILE_:

    The optional input for a file to save the public portion of endorsement key.

  * **-t**, **\--template**:

    The optional manufacturer defined endorsement key template and nonce from
    fixed NV Indices to populate the **TPM2B_PUBLIC** public area.
    See the TCG EK Credential Profile specification for more information:
    https://trustedcomputinggroup.org/wp-content/uploads/
    TCG_IWG_Credential_Profile_EK_V2.1_R13.pdf

[pubkey options](common/pubkey.md)

    Public key format.

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

# EXAMPLES

### Create an RSA Endorsement Key and make it persistent
```bash
tpm2_createek -P abc123 -w abc123 -c 0x81010001 -G rsa -u ek.pub
```

### Create an ECC NIST_P384 Endorsement Key and make it persistent
```bash
tpm2_createek -G ecc384 -c 0x81010002
```

### Create a transient Endorsement Key, flush it, and reload it.
Typically, when using the TPM, the interactions occur through a resource
manager, like tpm2-abrmd(8).  However, when interacting with the TPM directly,
this scenario is possible. The below example assumes direct TPM access not
brokered by a resource manager. Specifically we will use /dev/tpm0.

```bash
tpm2_createek -c ek.ctx -G rsa -u ek.pub -Tdevice:/dev/tpm0 

# Check that it is loaded in transient memory
tpm2_getcap handles-transient -Tdevice:/dev/tpm0 
- 0x80000000

# Flush the handle
tpm2_flushcontext 0x80000000 -Tdevice:/dev/tpm0

# Note that it is flushed
tpm2_getcap handles-transient -Tdevice:/dev/tpm0
<null output>

# Reload it via loadexternal
tpm2_loadexternal -C o -u ek.pub -c ek.ctx -Tdevice:/dev/tpm0

# Check that it is re-loaded in transient memory
tpm2_getcap handles-transient -Tdevice:/dev/tpm0
- 0x80000000

```

[returns](common/returns.md)

[footer](common/footer.md)
