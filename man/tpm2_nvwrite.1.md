% tpm2_nvwrite(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvwrite**(1) - Write data to a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvwrite** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvwrite**(1) - Write data specified via _FILE_ to a Non-Volatile (NV)
index. If _FILE_ is not specified, it defaults to stdin. The index is specified
as an argument and can be a raw handle or an offset value to the nv handle range
"TPM2_HR_NV_INDEX".

# OPTIONS

  * **ARGUMENT**=_NUMBER_

    Specify the NV index to write to as an offset to the starting NV index
    range or an absolute index value.
    Example: tpm2_nvwrite 1 is same as tpm2_nvwrite 0x01000001

  * **-i**, **\--input**=_FILE_:

    This is a mandatory input to specify the input file with data to write to
    NV. The input can also be specified from stdin with **-i-** option.

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

  * **\--offset**=_NATURAL_NUMBER_:

    The offset within the NV index to start writing at.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash unless rphash is
    also required.

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

## Write the file nv.data to index *0x01000001*
```bash
tpm2_nvdefine -Q   1 -C o -s 32 -a "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2_nvwrite -Q   1 -C o -i nv.test_w
```

[returns](common/returns.md)

[footer](common/footer.md)
