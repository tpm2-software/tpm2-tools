% tpm2_nvsetbits(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvsetbits**(1) - Bitwise OR bits into a Non-Volatile (NV).

# SYNOPSIS

**tpm2_nvsetbits** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvsetbits**(1) - Bitwise OR bits into a Non-Volatile (NV). The
NV index must be of type "bits" which is specified via the "nt" field
when creating the NV space with tpm2_nvdefine(1). The index can be
specified as raw handle or an offset value to the NV handle range
"TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-C** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-i**, **\--bits**=_BITS_:

    Specifies the bit value as a number to bitwise OR into the current value
    of the NV index.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

  * **-n**, **\--name**=_FILE_:

    The name of the NV index that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

  * **ARGUMENT** the command line argument specifies the NV index or offset
    number.

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

## OR 0xbadc0de into an index of 0's
```bash
tpm2_nvdefine -C o -a "nt=bits|ownerread|policywrite|ownerwrite|writedefine" 1

tpm2_nvsetbits -C o -i 0xbadc0de 1

tpm2_nvread -C o 1 | xxd -p | sed s/'^0*'/0x/
0xbadc0de
```

[returns](common/returns.md)

[footer](common/footer.md)
