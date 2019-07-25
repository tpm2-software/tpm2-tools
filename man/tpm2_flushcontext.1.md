% tpm2_flushcontext(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_flushcontext**(1) - Remove a specified handle, or all contexts associated with a
transient object, loaded session or saved session from the TPM.

# SYNOPSIS

**tpm2_flushcontext** [*OPTIONS*]

# DESCRIPTION

**tpm2_flushcontext**(1) - Remove a specified handle, or all contexts associated with a
transient object, loaded session or saved session from the TPM.

# OPTIONS

  * **-c**, **\--context**=_CONTEXT\_OBJECT_:

    The transient handle of the object to be flushed from the TPM. Must be a valid handle number.

  * **-t**, **\--transient-object**:

    Remove all transient objects.

  * **-l**, **\--loaded-session**:

    Remove all loaded sessions.

  * **-s**, **\--saved-session**:

    Remove all saved sessions.

  * **-S**, **\--session**=_SESSION\_FILE_:

    Obtain handle to flush from a session file. A session file is generated from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Flushing a Transient Object

Typically, when using the TPM, the interactions occur through a resource
manager, like tpm2-abrmd(8). When the process exits, transient object
handles are flushed. Thus, flushing transient objects through the command
line is not required. However, when interacting with the TPM directly,
this scenario is possible. The below example assumes direct TPM access not
brokered by a resource manager. Specifically we will use the simulator.

```bash
tpm2_createprimary -Tmssim -c primary.ctx

tpm2_getcap -T mssim handles-transient
- 0x80000000

tpm2_flushcontext -T mssim -c 0x80000000
```

## Flush All the Transient Objects
```bash
tpm2_flushcontext \--transient-object
```

## Flush a Session
```
tpm2_startauthsession -S session.dat

tpm2_flushcontext -S session.dat
```

# NOTES

If multiple options are specified (**-t**, **-s** or **-l**), only the last option will be taken into account.

[returns](common/returns.md)

[footer](common/footer.md)
