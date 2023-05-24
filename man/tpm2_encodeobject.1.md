% tpm2_encodeobject(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_encodeobject**(1) - Encode an object into a combined PEM format.

# SYNOPSIS

**tpm2_encodeobject** [*OPTIONS*]

# DESCRIPTION

**tpm2_encodeobject**(1) - Encode both the private and public portions of an
object into a combined PEM format used by tpm2-tss-engine.

The tool reads private and public portions of an object and encodes it
into a combined PEM format used by tpm2-tss-engine and other
applications.

**NOTE**: Both private and public portions of the tpm key must be specified.

# OPTIONS

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent object.

  * **-P**, **\--auth**=_AUTH_:

    The authorization value of the parent object specified by **-C**.

  * **-u**, **\--public**=_FILE_:

    A file containing the public portion of the object.

  * **-r**, **\--private**=_FILE_:

    A file containing the sensitive portion of the object.

  * **-p**, **\--key-auth**:

    Indicates if an authorization value is needed for the object specified by
    **-r** and **-u**.

  * **-o**, **\--output**=_FILE_:

    The output file path, recording the public portion of the object.

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

## Setup
To load an object you first must create an object under a primary object. So the
first step is to create the primary object.

```bash
tpm2_createprimary -c primary.ctx
```

Step 2 is to create an object under the primary object.

```bash
tpm2_create -C primary.ctx -u key.pub -r key.priv -f pem -o pub.pem
```

This creates the private and public portions of the TPM object. With these
object portions, it is now possible to load that object into the TPM for
subsequent use.

## Encoding an Object into a combined PEM format

The final step, is encoding the public and private portions of the object into a
PEM format.

```bash
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o priv.pem
```

The generated `priv.pem` can be used together with `pub.pem` created in the
step 2 of Setup section.

[returns](common/returns.md)

[footer](common/footer.md)
