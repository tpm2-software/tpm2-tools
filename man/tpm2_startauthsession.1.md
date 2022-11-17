% tpm2_startauthsession(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_startauthsession**(1) - Start a session with the TPM.

# SYNOPSIS

**tpm2_startauthsession** [*OPTIONS*]

# DESCRIPTION

**tpm2_startauthsession**(1) - Starts a session with the TPM. The default is to
start a *trial* session unless the **-a** option is specified. Saves the policy
session data to a file. This file can then be used in subsequent tools that can
use a policy file for authorization or policy events.

This will not work with resource managers (RMs) outside of
[tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd), as most RMs will flush
session handles when a client disconnects from the IPC channel. However, when using
a RM without the session gapping feature, one can use the command TCTI to keep the
connection open.

The first step is to create a socket listener that uses tpm2\_send:
```bash
mknod "$HOME/backpipe" p
while [ 1 ]; do tpm2_send 0<"$HOME/backpipe" | nc -lU "$HOME/sock" 1>"$HOME/backpipe"; done;
```

The next step is to use the command TCTI and netcat (nc) to send data to the socket.
```bash
tpm2_startauthsession --tcti="cmd:nc -q 0 -U $HOME/sock" <options>
```

When finishing ensure to kill the listener. For commands executed with the command tcti against
the listener, one will need to manage transient handles. The simplest way is to add a flush
after each command: `tpm2_flushcontext --tcti="cmd:nc -q 0 -U $HOME/sock" -t`

Note: This example uses UNIX sockets, since the socket is controlled with Linux
access controls. Using a port is not recommended as it's either open to any user
on the system (localhost) or bound to a network card and exposed to the network.

This will work with direct TPM access, but note that internally this calls a
*ContextSave* and a *ContextLoad* on the session handle, thus the session
**cannot** be saved/loaded again.

# OPTIONS

  * **\--policy-session**:

    Start a policy session of type **TPM_SE_POLICY**. Default without this
    option is **TPM_SE_TRIAL**.

    **NOTE**: A *trial* session is used when building a policy and a *policy*
    session is used when authenticating with a policy.

  * **\--audit-session**:

    Start an HMAC session to be used as an audit session. Default without
    this option is **TPM2_SE_TRIAL**.

  * **\--hmac-session**:

    Start an HMAC session of type **TPM_SE_HMAC**. Default without this option
    is **TPM2_SE_TRIAL**.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm used in computation of the policy digest.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The symmetric algorithm used in parameter encryption/decryption.

  * **-c**, **\--key-context**=_OBJECT_:

    Set the tpmkey and bind objects to be the same.
    Session parameter encryption is turned on.
    Session parameter decryption is turned on.
    Parameter encryption/decryption symmetric-key set to AES-CFB.

  * **-S**, **\--session**=_FILE_:

    The name of the policy session file, required.

  * **\--bind-context**=_FILE_:

    Set the bind object.
    Session parameter encryption is off. Use **tpm2_sessionconfig** to turn on.
    Session parameter decryption is off. Use **tpm2_sessionconfig** to turn on.
    Parameter encryption/decryption symmetric-key set to AES-CFB.

  * **\--bind-auth**=_AUTH_:

    Set the authorization value for the bind object.

  * **\--tpmkey-context**=_FILE_:

    Set the tpmkey object.
    Session parameter encryption is off. Use **tpm2_sessionconfig** to turn on.
    Session parameter decryption is off. Use **tpm2_sessionconfig** to turn on.
    Parameter encryption/decryption symmetric-key set to AES-CFB.

  * **-n**, **\--name**=_FILE_

    A name file as output from a tool like tpm2\_readpublic(1) `-n` option.
    The name file can be used to **verify** a persistent handle input for
    the `--tpmkey-context`, `-c`, and `--key-context` options. Verification
    that the object referenced by a peristent handle, e.g 0x81000000, is
    the key expected prevents attackers from performing a man-in-the-middle
    attack on session traffic.

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

## Start a *trial* session and save the session data to a file
```bash
tpm2_startauthsession -S mysession.ctx
```

## Start a *policy* session and save the session data to a file
```bash
tpm2_startauthsession --policy-session -S mysession.ctx
```

## Start an encrypted and bound *policy* session and save the session data to a file
```bash
tpm2_createprimary -c primary.ctx
tpm2_startauthsession --policy-session -c primary.ctx -S mysession.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
