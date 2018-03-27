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

  * **-x**, **--index**=_NV\_INDEX_:
    Specifies the index to define the space at.

  * **-a**, **--auth-handle**=_AUTH_:
    specifies the handle used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

    **NOTE**: To authorize against the index, specify the index handle as
    the argument to option **-a**. The index auth value is set via the
    **-I** option to tpm2_nvdefine(1).

  * **-f**, **--out-file**=_FILE_:
    file to write data

  * **-P**, **--auth-hierarchy**=_HIERARCHY\_AUTH_:
    Specifies the authorization value for the hierarchy. Authorization values
    should follow the authorization formatting standards, see section
    "Authorization Formatting".

  * **-s**, **--size**=_SIZE_:
    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * **-o**, **--offset**=_OFFSET_:
    The offset within the NV index to start reading from.

  * **-L**, **--set-list**==_PCR\_SELECTION\_LIST_:

    The list of pcr banks and selected PCRs' ids.
    _PCR\_SELECTION\_LIST_ values should follow the
    pcr bank specifiers standards, see section "PCR Bank Specfiers".

  * **-F**,**--pcr-input-file=_PCR\_INPUT\_FILE_

    Optional Path or Name of the file containing expected pcr values for the specified index.
    Default is to read the current PCRs per the set list.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/password.md)

# EXAMPLES

To read 32 bytes from an index starting at offset 0:

```
tpm2_nvread -x 0x1500016 -a 0x40000001 -s 32
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
