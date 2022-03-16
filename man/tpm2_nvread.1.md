% tpm2_nvread(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index.

# SYNOPSIS

**tpm2_nvread** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index. The
index can be specified as raw handle or an offset value to the nv handle range
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

  * **-o**, **\--output**=_FILE_:

    File to write data

  * **-P**, **\--auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

  * **-s**, **\--size**=_NATURAL_NUMBER_:

    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * **\--offset**=_NATURAL_NUMBER_:

    The offset within the NV index to start reading from.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is
    also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-n**, **\--name**=_FILE_:

    The name of the NV index that must be provided when only calculating the
    cpHash without actually dispatching the command to the TPM.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

  * **\--print-yaml**:

	Output the content of the NV index in a human readable format, useful
	for displaying the content of counter, bits and extend and pin indices.
	When this argument is provided size and offset is ignored.

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
the various known TCTI modules.d)

# EXAMPLES

## Read 32 bytes from an index starting at offset 0
```bash
tpm2_nvdefine -C o -s 32 -a "ownerread|policywrite|ownerwrite" 1

echo "please123abc" > nv.dat

tpm2_nvwrite -C o -i nv.dat 1

tpm2_nvread -C o -s 32 1
```

[returns](common/returns.md)

[footer](common/footer.md)
