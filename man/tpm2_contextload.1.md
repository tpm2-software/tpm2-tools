% tpm2_contextload(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_contextload**(1) - Loads the session into the TPM, so that it can be
referenced using the TPM session handle.

# SYNOPSIS

**tpm2_contextload** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_contextload**(1) - Loads the session into the TPM, so that it can be
referenced using the TPM session handle.

The tool returns the TPM handle the session is currently loaded on, and that
handle value can be used directly when communicating directly with the TPM.

**NOTE**: The session context file will not be usable on subsequent calls. As
all tools invoke contextload/contextsave before/after using the session, the
contextload call for subsequent commands will fail as the session is loaded
already.

**NOTE 2**: When working with the in-kernel resource manager, the contextload
command should be executed directly against the TPM (using the --tcti option)
, as the in-kernel RM flushes the objects upon exiting.

* **ARGUMENT** the session context file.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Create a policy session, contextload it into the TPM

```bash

tpm2 startauthsession -S session.ctx --policy-session

tpm2 contextload -T "device:/dev/tpm0" session.ctx

```

[returns](common/returns.md)

[footer](common/footer.md)
