% tpm2_nvreadlock(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvreadlock**(1) - Lock the Non-Volatile (NV) index for further reads.

# SYNOPSIS

**tpm2_nvreadlock** [*OPTIONS*] _NV\_INDEX_

# DESCRIPTION

**tpm2_nvreadlock**(1) - Lock the Non-Volatile (NV) index for further reads. The
lock on the NN index is unlocked when the TPM is restarted and the NV index
becomes readable again. The index can be specified as raw handle or an offset
value to the nv handle range "TPM2_HR_NV_INDEX".

# OPTIONS

  * **-C**, **\--hierarchy**=_AUTH_HANDLE_:

    Specifies the hierarchy used to authorize.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a hierarchy handle or nv-index may be used.

    When **-C** isn't explicitly passed the index handle will be used to
    authorize against the index. The index auth value is set via the
    **-p** option to **tpm2_nvdefine**(1).

  * **-P**, **\--auth**=_AUTH\_VALUE_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Lock an index
```bash
tpm2_nvdefine -Q   1 -C o -s 32 -a "ownerread|policywrite|ownerwrite|read_stclear"

echo "foobar" > nv.readlock

tpm2_nvwrite -Q   0x01000001 -C o -i nv.readlock

tpm2_nvread -Q   1 -C o -s 6 -o 0

tpm2_nvreadlock -Q   1 -C o
```

[returns](common/returns.md)

[footer](common/footer.md)
