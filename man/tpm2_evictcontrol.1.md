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

  * **-a**, **--hierarchy**=_AUTH\_HIERARCHY\_:

    The authorization hierarchy used to authorize the commands. Defaults to the "owner" hierarchy.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-c**, **--context**=_OBJECT_CONTEXT_:

    A context object specifier of a transient or persistent object.
    Either a file path of a handle id. See section "Context Object Format".

    If _OBJECT\_CONTEXT_ is for a transient object it will be persisted, either
    to the handle specified by the **-p** option, or to the first available vacant
    persistent handle.

    If the handle is for a persistent object, then the **-p** does not need to
    be provided since the handle must be the same for both options.

  * **-p**, **--persistent**=_PERSISTENT\_HANDLE_:

    The persistent handle for the object handle specified via _HANDLE_.

  * **-P**, **--auth-hierarchy**=_AUTH\_HIERARCHY_\VALUE_:

    Optional authorization value. Authorization values should follow the
    authorization formatting standards, see section "Authorization Formatting".

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](commmon/ctxobj.md)

[authorization formatting](common/password.md)

# EXAMPLES

```
tpm2_evictcontrol -A o -c object.context -S 0x81010002 -P abc123
tpm2_evictcontrol -A o -c 0x81010002 -S 0x81010002 -P abc123
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
