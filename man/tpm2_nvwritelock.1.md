% tpm2_nvwritelock(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_nvwritelock**(1) - Lock the Non-Volatile (NV) index for further writes.

# SYNOPSIS

**tpm2_nvwritelock** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_nvwritelock**(1) - Lock the Non-Volatile (NV) index for further writes. The
lock on the NV index is unlocked when the TPM is restarted and the NV index
becomes writable again. The index can be specified as raw handle or an offset
value to the nv handle range "TPM2_HR_NV_INDEX".

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

  * **\--global**:

    Lock all NV indices with attribute TPMA\_NV\_GLOBALLOCK. This option
    does not require an NV index or offset as an argument.

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

## Lock an index
```bash
tpm2_nvdefine -C o -s 32 \
  -a "ownerread|policywrite|ownerwrite|writedefine" 1

echo "foobar" > nv.writelock

tpm2_nvwrite -C o -i nv.writelock 1

tpm2_nvwritelock -C o 1

# fails with "NV access locked"
tpm2_nvwrite -C o -i nv.writelock 1
```

## Global Lock
```bash
tpm2_nvdefine -C o -s 32 \
  -a "ownerread|policywrite|ownerwrite|globallock" 1

tpm2_nvwritelock -C o --global

# this command fails with "NV access locked".
echo foo | tpm2_nvwrite -C o -i- 1
```

[returns](common/returns.md)

[footer](common/footer.md)
