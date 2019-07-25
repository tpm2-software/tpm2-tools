% tpm2_nvread(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index.

# SYNOPSIS

**tpm2_nvread** [*OPTIONS*] _NV\_INDEX_

# DESCRIPTION

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index. The
index can be specified as raw handle or an offset value to the nv handle range
"TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_AUTH_:

    Specifies the hierarchy used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-a** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-o**, **\--output**=_FILE_:

    File to write data

  * **-P**, **\--auth**=_AUTH\_HIERARCHY\_VALUE__:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-s**, **\--size**=_SIZE_:

    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * **\--offset**=_OFFSET_:

    The offset within the NV index to start reading from.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[PCR bank specifiers](common/pcr.md)

# EXAMPLES

## Read 32 bytes from an index starting at offset 0
```
tpm2_nvdefine -Q  1 -C o -s 32 -a "ownerread|policywrite|ownerwrite"

echo "please123abc" > nv.test_w

tpm2_nvwrite -Q -x $nv_test_index -C o nv.test_w

tpm2_nvread -Q  1 -C o -s 32 -o 0
```

[returns](common/returns.md)

[footer](common/footer.md)
