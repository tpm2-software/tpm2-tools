% tpm2_nvwrite(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvwrite**(1) - Write data to a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvwrite** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_nvwrite**(1) - Write data specified via _FILE_ to a Non-Volatile (NV) index.
If _FILE_ is not specified, it defaults to stdin.

# OPTIONS

  * **-x**, **\--index**=_NV\_INDEX_:

    Specifies the index to define the space at.

  * **-a**, **\--hierarchy**=_AUTH_:

    Specifies the handle used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

    When **-a** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth-hierarchy**=_HIERARCHY\_AUTH_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **\--offset**=_OFFSET_:

    The offset within the NV index to start writing at.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[PCR bank specifiers](common/pcr.md)

# EXAMPLES

## Write the file nv.data to index *0x150016*
```
tpm2_nvwrite -x 0x1500016 -P "index" -f nv.data
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
