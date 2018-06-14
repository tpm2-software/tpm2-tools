% tpm2_createak(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_createak**(1) - Generate attestation key with given algorithm under the
endorsement hierarchy.

# SYNOPSIS

**tpm2_createak** [*OPTIONS*]

# DESCRIPTION

**tpm2_createak**(1) - Generate an attestation key (AK) with the given
algorithm under the endorsement hierarchy. It also makes it persistent
with given AK handle supplied via **-k**. If **-p** is specified, the
tool outputs the public key to the path supplied as the option argument.

If any password option is missing, assume NULL.

The tool outputs to stdout a YAML representation of the loaded key handle
as well as it's name, for example:
```
loaded-key:
  handle: 800000ff
  name: 000bac149518baa05540a0678bd9b624f8a98d042e46c60f4d098ba394d36fc49268
```

# OPTIONS

  * **-E**, **--auth-endorse**=_ENDORSE\_AUTH_:
    Specifies current endorsement authorization.
    Authorizations should follow the "authorization formatting standards, see section
    "Authorization Formatting".

  * **-P**, **--auth-ak**=_AK\_AUTH_
    Specifies the AK authorization when created.
    Same formatting as the endorse authorization value or **-e** option.

  * **-o**, **--auth-owner**=_OWNER\_AUTH_
    Specifies the current owner authorization.
    Same formatting as the endorse password value or **-e** option.

  * **-C**, **--ek-context**=_EK\_CONTEXT\_OBJECT_:
    Specifies the object context of the EK. Either a file or a handle number.
    See section "Context Object Format".

  * **-k**, **--ak-handle**=_AK\_HANDLE_:
    Specifies the handle used to make AK persistent.
    If a value of **-** is passed the tool will find a vacant persistent handle
    to use and print out the automatically selected handle.

  * **-c**, **--context**=_PATH_:
    Optional, specifies a path to save the context of the AK handle. If one saves
    the context file via this option and the public key via the **-p** option, the
    AK can be restored via a call to tpm2_loadexternal(1).

  * **-g**, **--algorithm**=_ALGORITHM_:
    Specifies the algorithm type of AK. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms.

  * **-D**, **--digest-alg**=_HASH\_ALGORITHM_:
    Like -g, but specifies the digest algorithm. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    See section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-s**, **--sign-alg**=_SIGN\_ALGORITHM_:
    Like -g but specifies signing algorithm. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    See section "Supported Signing Algorithms" for a list of supported
    signing algorithms.

  * **-p**, **--file**=_FILE_:
    Specifies the file used to save the public portion of AK. This will be a
    binary data structure corresponding to the TPM2B_PUBLIC struct in the
    specification. One can control the output to other formats via the
    **--format** option.

  * **-n**, **--ak-name**=_NAME_:
    Specifies the file used to save the ak name, optional.

  * **-r**, **--privfile**=_OUTPUT\_PRIVATE\_FILE_:
    The output file which contains the sensitive portion of the object, optional.
    If the object is an asymmetric key-pair, then this is the private key.

[pubkey options](common/pubkey.md)

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[context object format](commmon/ctxobj.md)

[supported signing algorithms](common/sign-alg.md)

[supported public object algorithms](common/object-alg.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES
## With a Resource Manager (RM)

Resource managers will flush the TPM context when a tool exits, thus
when using an RM, moving the created EK to persistent memory is
required.

Create an Attestation Key and make it persistent:
```
# create an Endorsement Key (EK)
tpm2_createek -c 0x81010001 -g rsa -p ek.pub
# create an Attestation Key (AK) passing the EK handle
tpm2_createak -C 0x81010001 -k 0x81010002 -p ./ak.pub -n ./ak.name
```

## Without a Resource Manager (RM)

The following examples will not work when an RM is in use, as the RM will
flush the TPM context when the tool exits. In these scenarios, the created
AK is in transient memory and thus will be flushed.

Create a transient Attestation Key, evict it, and reload it:
```
# AK needs an Endorsement Key (primary object)
tpm2_createek
0x80000000

# Now create a transient AK
tpm2_createak -C 0x80000000 -o ak.ctx -p ak.pub -n ak.name
loaded-key:
  handle: 0x80000001
  name: 000b8052c63861b1855c91edd63bca2eb3ea3ad304bb9798a9445ada12d5b5bb36e0

tpm2_createek -g rsa -p ek.pub -c ek.ctx

# Check that the AK is loaded in transient memory
# Note the AK is at handle 0x80000001
tpm2_getcap -c handles-transient
- 0x80000000
- 0x80000001

# Flush the AK handle
tpm2_flushcontext -H 0x80000000

# Note that it is flushed
tpm2_getcap -c handles-transient
- 0x80000000

# Reload it via loadexternal
tpm2_loadexternal -H o -u ak.pub -o ak.ctx

# Check that it is re-loaded in transient memory
$ tpm2_getcap -c handles-transient
- 0x80000000
- 0x80000001

```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
