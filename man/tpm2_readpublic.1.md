% tpm2_readpublic(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_readpublic**(1) - Read the public area of a loaded object.

# SYNOPSIS

**tpm2_readpublic** [*OPTIONS*]

# DESCRIPTION

**tpm2_readpublic**(1) - Reads the public area of a loaded object.

# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    Context object for the object to read.

  * **-n**, **\--name**=_FILE_:

    An optional file to save the name structure of the object.

[pubkey options](common/pubkey.md)

    Public key format.

  * **-o**, **\--output**=_FILE_:

    The output file path, recording the public portion of the object.

  * **-t**, **\--serialized-handle**=_HANDLE_:

    If the object to be read is a persistent object specified by a raw handle,
    optionally save the serialized handle for use later. This routine does NOT verify the name of the object being read. Callers should ensure that the
    contents of name match the expected objects name.

  * **-q**, **\--qualified-name**=_FILE_:

    Saves the qualified name of the object to _FILE_. The qualified name of the object is the name algorithm hash of
    the parents qualified and the objects name. Thus the qualified name of the object serves as proof of the objects
    parents.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.
# EXAMPLES

## Create a primary object and read the public structure in an openssl compliant format
```bash
tpm2_createprimary -c primary.ctx
tpm2_readpublic -c primary.ctx -o output.dat -f pem
```

## Serialize an existing persistent object handle to disk for later use

This work-flow is primarily intended for existing persistent TPM objects. This
work-flow does not verify that the name of the serialized object matches the
expected, and thus the serialized handle could be pointing to an attacker
controlled object if no verification is done. If you are creating an object from
scratch, save the serialized handle when making the object persistent.

We assume that an object has already been persisted, for example via:

```bash
# We assume that an object has already been persisted, for example
tpm2_createprimary -c primary.ctx

# context files have all the information for the TPM to verify the object
tpm2_evictcontrol -c primary.ctx
persistent-handle: 0x81000001
action: persisted
```

Next use the persistent handle to get a serialized handle:

```bash
# The persistent handle output could be at an attacker controlled object,
# best practice is to use the option "-o: for tpm2_evictcontrol to get a
# serialized handle instead.

tpm2_readpublic -c 0x81000001 -o output.dat -f pem -t primary.handle

# use this verified handle in an encrypted session with the tpm
tpm2_startauthsession --policy-session -S session.ctx -c primary.handle
```

For new objects, its best to use all serialized handles.

[returns](common/returns.md)

[footer](common/footer.md)
