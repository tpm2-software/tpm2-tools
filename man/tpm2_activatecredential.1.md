% tpm2_activatecredential(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_activatecredential**(1) - verify that an object is protected with a specific
key.

# SYNOPSIS

**tpm2_activatecredential** [*OPTIONS*]

# DESCRIPTION

Verify that the given content is protected with given keyHandle for given
handle, and then decrypt and return the secret, if any passwd option is
missing, assume NULL. Currently only support using TCG profile compliant EK as
the keyHandle.

# OPTIONS

These options control the object verification:

  * **-c**, **--context**=_OBJ\_CTX_:
    _CONTEXT_ of the object associated with the created certificate by CA.

  * **-H**, **--handle**=_HANDLE_:
    _HANDLE_ of the object associated with the created certificate by CA.

  * **-k**, **--key-handle**=_KEY\_HANDLE_:
    The _KEY\_HANDLE_ of Loaded key used to decrypt the the random seed.

  * **-C**, **--key-context**=_KEY\_CONTEXT\_FILE_:
    _KEY\_CONTEXT\_FILE_ is the path to a context file.

  * **-P**, **--password**=_PASSWORD_:
    Use _PASSWORD_ for providing an authorization value for the _KEY\_HANDLE_.
    Passwords should follow the "password formatting standards, see section "Password Formatting".

  * **-e**, **--endorse-passwd**=_ENDORSE\_PASSWORD_:
    The endorsement password, optional. Follows the same formating guidelines as the handle password option -P.

  * **-f**, **--in-file**=_INPUT\_FILE_:
    Input file path, containing the two structures needed by tpm2_activatecredential function. This is created
    via the tpm2_makecredential(1) command.

  * **-o**, **--out-file**=_OUTPUT\_FILE_:
    Output file path, record the secret to decrypt  the certificate.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

# EXAMPLES

```
tpm2_activatecredential -H 0x81010002 -k 0x81010001 -P abc123 -e abc123 -f <filePath> -o <filePath>
tpm2_activatecredential -c ak.context -C ek.context -P abc123 -e abc123 -f <filePath> -o <filePath>
tpm2_activatecredential -H 0x81010002 -k 0x81010001 -P 123abc -e 1a1b1c -f <filePath> -o <filePath>
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
