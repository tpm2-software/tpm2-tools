% tpm2_gettime(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_gettime**(1) - Get the current time and clock from the TPM in a signed form.

# SYNOPSIS

**tpm2_gettime** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_gettime**(1) - Provides a signed copy of the current time and clock from the TPM.
It returns both a signature, and the data in the standard TPM attestation form, a TPMS\_ATTEST
structure.

It outputs to stdout, in YAML format, the TPMS\_TIME\_INFO structure from the TPM. The structure contains the
current setting of Time, Clock, resetCount, and restartCount. The structure is output as
YAML defined as:

```yaml
time: 13673142     # 64 bit value of time since last _TPM_Init or TPM2_Startup
                   # in ms.
clock_info:
  clock: 13673142  # 64 bit value of time TPM has been powered on in ms.
  reset_count: 0   # 32 bit value of the number of TPM Resets since the last
                   # TPM2_Clear.
  restart_count: 0 # 32 bit value of the number of times that TPM2_Shutdown or
                   # _TPM_Hash_Start have occurred since the last TPM Reset or
                   # TPM2_Clear.
  safe: yes        # boolean yes|no value that no value of Clock greater than
                   # the current value of Clock has been previously reported by
                   # the TPM.
```

# OPTIONS

  * **-c**, **\--key-context**=_OBJECT_:

    Context object pointing to the the key used for signing.
    Either a file or a handle number. See section "Context Object Format".

  * **-p**, **\--auth**_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-P**, **\--endorse-auth**_AUTH_:

    Optional authorization value for the endorsement hierarchy.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used to digest the message.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-s**, **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the message. Optional.
    Signing schemes should follow the "formatting standards", see section
     "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported
     signature schemes.
    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
     be used.

  * **-q**, **\--qualification**=_FILE\_OR\_HEX\_STR_:

    Optional, the policy qualifier data that the signer can choose to include in the
    signature. Can be either a hex string or path.

  * **-o**, **\--signature**=_FILE_:

    The signature file, records the signature structure.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file. See section
    "Signature Format Specifiers".

  * **--attestation**=_FILE_:

    The attestation data of the type TPMS_ATTEST signed with signing key.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the file data for sign.

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
[signature format specifiers](common/signature.md)

# EXAMPLES

## Create a key and get attested TPM time

```bash
tpm2_createprimary -C e -c primary.ctx

tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx

tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx

tpm2_gettime -c rsa.ctx -o attest.sig --attestation attest.data
```

[returns](common/returns.md)

[footer](common/footer.md)
