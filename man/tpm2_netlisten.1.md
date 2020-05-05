% tpm2_clear(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_netlisten**(1) - Listens for client connections on an unsecured network socket.

# SYNOPSIS

**tpm2_netlisten** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_netlisten**(1) - Listens for client connections on an unsecure network port and
transfers tpm2 command buffersthem from the client to the configured tcti, and replies
with tpm2 reposne buffers. By default it listens on port 29100 bound to the localhost,
however argument is any valid network TCTI conf string. See man **tss2-tcti-network(7)**.

**WARNING**
All communication is plaintext thus:
- authvalues are visible
- MITM attacks possible
unless using properly established encrypted sessions.
Authorizations are only enforced by the TPM, anyone can access this port.
Their is no Authentication done.

** The use of a secure tunneling agent like SSH is highly encouraged **

# OPTIONS

  * **ARGUMENT** the command line argument specifies the _CONF_ string to be used
    to intialize the network tcti.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## TODO WITH SSH TUNNEL

[returns](common/returns.md)

[footer](common/footer.md)
