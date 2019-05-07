% tpm2_readpublic(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_readpublic**(1) - Read the public area of a loaded object.

# SYNOPSIS

**tpm2_readpublic** [*OPTIONS*]

# DESCRIPTION

**tpm2_readpublic**(1) - Reads the public area of a loaded object.

# OPTIONS

  * **-c**, **\--context**=_OBJECT\_CONTEXT_:

    Context object for the object to read. Either a file, a serialized handle or a handle number.
    See section "Context Object Format".

  * **-n**, **\--name**=_NAME\_DATA\_FILE_:

    An optional file to save the name structure of the object.

  * **-o**, **\--out-file**=_OUT\_FILE_:

    The output file path, recording the public portion of the object.

  * **-t**, **\--serialized-handle**=_OUT\_HANDLE\_:

    If the object to be read is a persistent object specified by a raw handle, optionally save the
    serialized handle for use later. This routine does NOT verify the name of the object being read.
    Callers should ensure that the contents of name match the expected objects name.

[pubkey options](common/pubkey.md)

[context object format](common/ctxobj.md)

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

## Create a primary object and read the public structure in an openssl compliant format
```
tpm2_createprimary -o primary.ctx
tpm2_readpublic -c primary.ctx -o output.dat -f pem
```

## Serialize an existing persistent object handle to disk for later use

This work-flow is primarily intended for existing persistent TPM objects. This work-flow does
not verify that the name of the serialized object matches the expected, and thus the serialized
handle could be pointing to an attacker controlled object if no verification is done. If you are
creating an object from scratch, save the serialized handle when making the object persistent.

We assume that an object has already been persisted, for example via:

```
# We assume that an object has already been persisted, for example
tpm2_createprimary -o primary.ctx

# context files have all the information for the TPM to verify the object
tpm2_evictcontrol -c primary.ctx
persistent-handle: 0x81000001
action: persisted
```

Next use the persistent handle to get a serialized handle:

```
# The persistent handle output could be at an attacker controlled object,
# best practice is to use the option "-o: for tpm2_evictcontrol to get a
# serialized handle instead.

tpm2_readpublic -c 0x81000001 -o output.dat -f pem -t primary.handle

tpm2_startauthsession --policy-session -S session.ctx -k primary.handle
```

For new objects, its best to use all serialized handles.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
