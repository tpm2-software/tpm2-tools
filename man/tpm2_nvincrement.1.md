% tpm2_nvincrement(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvincrement**(1) - Increment counter in a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvincrement** [*OPTIONS*] _NV\_INDEX_

# DESCRIPTION

**tpm2_nvincrement**(1) - Increment value of a Non-Volatile (NV) index setup as
a counter. The index can be specified as raw handle or an offset value to the nv
handle range "TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_AUTH_:

    Specifies the handle used to authorize. Defaults to **o**, **TPM_RH_OWNER**,
    when no value has been specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-C** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth**=_HIERARCHY\_AUTH_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[PCR bank specifiers](common/pcr.md)

# EXAMPLES

## To increment the counter at index *0x150016*

```
tpm2_nvdefine -C 0x1500016 -s 8 -a "ownerread|policywrite|ownerwrite|nt=1" \
0x1500016 -p index

tpm2_nvincrement   0x1500016 -P "index"
```

[returns](common/returns.md)

[footer](common/footer.md)
