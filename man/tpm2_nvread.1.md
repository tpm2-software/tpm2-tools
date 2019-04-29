% tpm2_nvread(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index.

# SYNOPSIS

**tpm2_nvread** [*OPTIONS*]

# DESCRIPTION

**tpm2_nvread**(1) - Read the data stored in a Non-Volatile (NV)s index.

# OPTIONS

  * **-x**, **\--index**=_NV\_INDEX_:

    Specifies the index to define the space at.

  * **-a**, **\--hierarchy**=_AUTH_:

    Specifies the hierarchy used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

    When **-a** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-o**, **\--out-file**=_FILE_:

    File to write data

  * **-P**, **\--auth-hierarchy**=_AUTH\_HIERARCHY\_VALUE__:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-s**, **\--size**=_SIZE_:

    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * **-L**, **\--set-list**==_PCR\_SELECTION\_LIST_:

    The list of PCR banks and selected PCRs' ids.
    _PCR\_SELECTION\_LIST_ values should follow the
    PCR bank specifiers standards, see section "PCR Bank Specifiers".

  * **-F**,**\--pcr-input-file=_PCR\_INPUT\_FILE_

    Optional Path or Name of the file containing expected PCR values for the specified index.
    Default is to read the current PCRs per the set list.

  * **\--offset**=_OFFSET_:

    The offset within the NV index to start reading from.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[PCR bank specifiers](common/pcr.md)

# EXAMPLES

## Read 32 bytes from an index starting at offset 0
```
tpm2_nvread -x 0x1500016 -a 0x40000001 -s 32
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
