% tpm2_load(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_load**(1) - Load an object into the TPM.

# SYNOPSIS

**tpm2_load** [*OPTIONS*]

# DESCRIPTION

**tpm2_load**(1) - Load both the private and public portions of an object
into the TPM or load the object in the TSS2-Private-Key PEM format. This can
be done by specifying the private as well as the public section or via a pem
file using the *-r* option.

The tool outputs the name of the loaded object in a YAML dictionary format
with the key *name* where the value for that key is the name of the object
in hex format, for example:
```yaml
name: 000bac25cb8743111c8e1f52f2ee7279d05d3902a18dd1af694db5d1afa7adf1c8b3
```

It also saves a context file for future interactions with the object.

**NOTE**: Both private and public portions of the tpm key must be specified.
The exception to this is if a TSS2-Private-Key formatted PEM object is to be
loaded which does not need the public specified.

# OPTIONS

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent object.

  * **-P**, **\--auth**=_AUTH_:

    The authorization value of the parent object specified by **-C**.

  * **-u**, **\--public**=_FILE_:

    A file containing the public portion of the object.

  * **-r**, **\--private**=_FILE_:

    A file containing the sensitive portion of the object.

  * **-n**, **\--name**=_FILE_:

    An optional file to save the name structure of the object.

  * **-c**, **\--key-context**=_FILE_:

    The file name of the saved object context, required.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

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
To load an object you first must create an object under a primary object. So the first
step is to create the primary object.

```bash
tpm2_createprimary -c primary.ctx
```

Step 2 is to create an object under the primary object.

```bash
tpm2_create -C primary.ctx -u key.pub -r key.priv
```

This creates the private and public portions of the TPM object. With these object
portions, it is now possible to load that object into the TPM for subsequent use.

## Loading an Object into the TPM

The final step, is loading the public and private portions of the object into the TPM.

```bash
tpm2_load  -C primary.ctx -u key.pub -r key.priv -c key.ctx
name: 000bac25cb8743111c8e1f52f2ee7279d05d3902a18dd1af694db5d1afa7adf1c8b3
```

[returns](common/returns.md)

[footer](common/footer.md)
