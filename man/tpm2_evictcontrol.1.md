% tpm2_evictcontrol(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_evictcontrol**(1) - Make a transient object persistent or evict a
persistent object.

# SYNOPSIS

**tpm2_evictcontrol** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_evictcontrol**(1) - Allows a transient object to be made persistent or a
persistent object to
be evicted. The _HANDLE_ argument controls the index the handle will be assigned
to. If the object specified via **-c** is transient, and a permanent _HANDLE_ is
specified, the object will be persisted at _HANDLE_. If _HANDLE_ is a -, then
the object will be persisted at the first available permanent handle location.
If the object specified via **-c** is a permanent handle, then the object will
be evicted from it's permenent handle location.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    The authorization hierarchy used to authorize the commands. Defaults to the
    "owner" hierarchy. Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-c**, **\--object-context**=_OBJECT_:

    A context object specifier of a transient or persistent object.
    If _OBJECT_ is a transient object it will be persisted, either to the handle
    specified by the argument or to first available vacant persistent handle.
    If the _OBJECT_ is for a persistent object, then the object will be evicted
    from non-volatile memory.

  * **-P**, **\--auth**=_AUTH_:

    The authorization value for the hierarchy specified with **-C**.

  * **-o**, **\--output**=_FILE_:

    Optionally output a serialized object representing the persistent handle.
    If untampered, these files are safer to use then raw persistent handles. A
    raw persistent handle should be verified that the object it points to is
    as expected.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

  * **ARGUMENT** the command line argument specifies the persistent handle to
    save the transient object to.

# Output
The tool outputs a YAML compliant dictionary with the fields:
persistent-handle: <handle>
action: evicted|persisted

Where *persistent-handle* is the handle the action occurred to.
Where *action* can either be one of *evicted* or *persisted*. If an object is
*evicted* then the object is no longer resident at the *persistent-handle*
address within the TPM. If an object is *persisted* then the object is resident
at the *persistent-handle* address within the TPM.

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

## To make a transient handle persistent at address 0x81010002
```bash
tpm2_changeauth -c o ownerauth
tpm2_createprimary -c primary.ctx -P ownerauth
tpm2_evictcontrol -C o -c primary.ctx 0x81010002 -P ownerauth
```

## To evict a persistent handle
```bash
tpm2_evictcontrol -C o -c 0x81010002 -P ownerauth
```

## To make a transient handle persistent and output a serialized persistent handle.
```bash
tpm2_evictcontrol -C o -c primary.ctx -o primary.handle -P ownerauth
```

[returns](common/returns.md)

[footer](common/footer.md)
