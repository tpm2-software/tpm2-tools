% tpm2_nvincrement(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvincrement**(1) - Increment counter in a Non-Volatile (NV) index.

# SYNOPSIS

**tpm2_nvincrement** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvincrement**(1) - Increment value of a Non-Volatile (NV) index setup as
a counter. The index can be specified as raw handle or an offset value to the nv
handle range "TPM2_HR_NV_INDEX".

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

## To increment the counter at index *0x150016*

```bash
tpm2_nvdefine -C 0x1500016 -s 8 -a "ownerread|policywrite|ownerwrite|nt=1" \
0x1500016 -p index

tpm2_nvincrement   0x1500016 -P "index"
```

[returns](common/returns.md)

[footer](common/footer.md)
