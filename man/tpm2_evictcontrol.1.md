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
    The authorization used to authorize the commands. Valid choices are:
    *  **o** for **TPM_RH_OWNER**
    *  **p** for **TPM_RH_PLATFORM**

  * **-H**, **--handle**=_HANDLE_:
    The handle of a loaded transient or a persistent object.

    If the handle is for a transient object, then a handle that will be assigned to the persisted
    object must also be specified with the **-S** option.

    If the handle is for a persistent object, then the **-S** does not need to be provided since the
    handle must be the same for both options.

  * **-c**, **--context**=_OBJECT\_CONTEXT\_FILE_:
    Filename for object context.

  * **-S**, **--persistent**=_PERSISTENT\_HANDLE_:
    The persistent handle for the object handle specified via _HANDLE_.

  * **-P**, **--pwda**=_AUTH\_PASSWORD_:
    authorization password, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-i**, **--input-session-handle**=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

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
