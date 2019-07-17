% tpm2_evictcontrol(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_evictcontrol**(1) - Make a transient object persistent or evict a persistent object.

# SYNOPSIS

**tpm2_evictcontrol** [*OPTIONS*]

# DESCRIPTION

**tpm2_evictcontrol**(1) - Allows a transient object to be made persistent or a persistent object to
be evicted.

# OPTIONS

  * **-C**, **\--hierarchy**=_AUTH\_HIERARCHY\_:

    The authorization hierarchy used to authorize the commands. Defaults to the "owner" hierarchy.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-c**, **\--context**=_OBJECT_CONTEXT_:

    A context object specifier of a transient or persistent object.
    Either a file path of a context blob or a handle id. See section "Context Object Format".

    If _OBJECT\_CONTEXT_ is for a transient object it will be persisted, either
    to the handle specified by the argument or to the first available vacant
    persistent handle.

    If the handle is for a persistent object, then the object will be evicted from
    non-volatile memory.

  * **-P**, **\--auth-hierarchy**=_AUTH\_HIERARCHY_\VALUE_:

    Optional authorization value. Authorization values should follow the
    "authorization formatting standards", see section "Authorization Formatting".

  * **-o**, **\--output**=_ESYS\_TR_\OBJECT:

    Optionally output a serialized object representing the persistent handle.
    If untampered, these files are safer to use then raw persistent handles. A
    raw persistent handle should be verified that the object it points to is
    as expected.

# Output
The tool outputs a YAML compliant dictionary with the fields:
persistent-handle: <handle>
action: evicted|persisted

Where *persistent-handle* is the handle the action occurred to.
Where *action* can either be one of *evicted* or *persisted*. If an object is
*evicted* then the object is no longer resident at the *persistent-handle* address
within the TPM. If an object is *persisted* then the object is resident at the
*persistent-handle* address within the TPM.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## To make a transient handle persistent at address 0x81010002
```
tpm2_evictcontrol -C o -c object.context -P abc123 0x81010002
```

## To evict a persistent handle
```
tpm2_evictcontrol -C o -c 0x81010002 -P abc123
```

## To make a transient handle persistent and output a serialized persistent handle.
```
tpm2_createprimary -o primary.ctx
tpm2_evictcontrol -C o -c primary.ctx -o primary.handle
```

[returns](common/returns.md)

[footer](common/footer.md)
