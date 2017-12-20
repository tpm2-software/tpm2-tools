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

  * **-H**, **--handle**=_HANDLE_:
    The handle of a object, loaded session or saved session to be removed.

  * **-t**, **--transient-object**:
    Remove all transient objects.

  * **-l**, **--loaded-session**:
    Remove all loaded sessions.

  * **-s**, **--saved-session**:
    Remove all saved sessions.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```
tpm2_flushcontext -H 0x80000000
tpm2_flushcontext --transient-object
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
