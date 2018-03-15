% tpm2_evictcontrol(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_evictcontrol**(1) - Make a transient object persistent or evict a persistent object.

# SYNOPSIS

**tpm2_evictcontrol** [*OPTIONS*]

# DESCRIPTION

**tpm2_evictcontrol**(1) - allows a transient object to be made persistent or a persistent object to
be evicted.

# OPTIONS

  * **-A**, **--auth**=_AUTH_:
    The authorization used to authorize the commands. Defaults to the "owner" hierarchy.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-H**, **--handle**=_HANDLE_:
    The handle of a loaded transient or a persistent object.

    If the handle is for a transient object, then a handle that will be assigned to the persisted
    object must also be specified with the **-p** option.

    If the handle is for a persistent object, then the **-p** does not need to be provided since the
    handle must be the same for both options.

  * **-c**, **--context**=_OBJECT\_CONTEXT\_FILE_:
    Filename for object context.

  * **-p**, **--persistent**=_PERSISTENT\_HANDLE_:
    The persistent handle for the object handle specified via _HANDLE_.

  * **-P**, **--pwda**=_AUTH\_PASSWORD_:
    authorization password, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

```
tpm2_evictcontrol -A o -c object.context -S 0x81010002 -P abc123
tpm2_evictcontrol -A o -H 0x81010002 -S 0x81010002 -P abc123
tpm2_evictcontrol -A o -H 0x81010002 -S 0x81010002 -P 123abc
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
