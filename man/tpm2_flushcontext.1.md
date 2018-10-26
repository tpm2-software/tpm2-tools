% tpm2_flushcontext(1) tpm2-tools | General Commands Manual
%
% NOVEMBER 2017

# NAME

**tpm2_flushcontext**(1) - Remove a specified handle, or all contexts associated with a transient object, loaded session or saved session from the TPM.

# SYNOPSIS

**tpm2_flushcontext** [*OPTIONS*]

# DESCRIPTION

**tpm2_flushcontext**(1) - remove a specified handle, or all contexts associated with a transient object, loaded session or saved session from the TPM.

# OPTIONS

  * **-c**, **--context**=_CONTEXT\_OBJECT_:
    The handle or session file of an object, loaded session or saved session to be removed.
    See section "Context Object Format".

  * **-t**, **--transient-object**:
    Remove all transient objects.

  * **-l**, **--loaded-session**:
    Remove all loaded sessions.

  * **-s**, **--saved-session**:
    Remove all saved sessions.

  * **-S**, **--session**=_SESSION\_FILE_:

    Obtain handle to flush from a session file. A session file is generated
    from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

# EXAMPLES

```
tpm2_flushcontext -c 0x80000000
tpm2_flushcontext --transient-object
```

Flushing a context via a session file
```
tpm2_startauthsession -S session.dat
tpm2_flushcontext -S session.dat
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
