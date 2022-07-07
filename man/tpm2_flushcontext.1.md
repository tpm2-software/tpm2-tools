% tpm2_flushcontext(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_flushcontext**(1) - Remove a specified handle, or all contexts associated
with a transient object, loaded session or saved session from the TPM.

# SYNOPSIS

**tpm2_flushcontext** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_flushcontext**(1) - Remove a specified handle, or all contexts associated
with a transient object, loaded session or saved session from the TPM. The
object to be flushed is specified as the first argument to the tool and is in
one of the following forms:
  - The handle of the object to be flushed from the TPM. Must be a valid handle
  number.
  - Flush a session via a session file. A session file is generated from
    **tpm2_startauthsession**(1)'s **-S** option.

# OPTIONS

  * **-t**, **\--transient-object**:

    Remove all transient objects.

  * **-l**, **\--loaded-session**:

    Remove all loaded sessions.

  * **-s**, **\--saved-session**:

    Remove all saved sessions.

  * **ARGUMENT** the command line argument specifies the _OBJECT_ to be removed
    from the TPM resident memory.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Flushing a Transient Object

Typically, when using the TPM, the interactions occur through a resource
manager, like tpm2-abrmd(8). When the process exits, transient object handles
are flushed. Thus, flushing transient objects through the command line is not
required. However, when interacting with the TPM directly, this scenario is
possible. The below example assumes direct TPM access not brokered by a resource
manager. Specifically we will use the simulator.

```bash
tpm2_createprimary -Tmssim -c primary.ctx

tpm2_getcap -T mssim handles-transient
- 0x80000000

tpm2_flushcontext -T mssim 0x80000000
```

## Flush All the Transient Objects
```bash
tpm2_flushcontext \--transient-object
```

## Flush a Session
```bash
tpm2_startauthsession -S session.dat

tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
