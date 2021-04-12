% tpm2_sessionconfig(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_sessionconfig**(1) - Configure session attributes and print session info
from a session file.

# SYNOPSIS

**tpm2_sessionconfig** [*OPTIONS*] [*ARGUMENT*]

# DESCRIPTION

**tpm2_sessionconfig**(1) - Configure session attributes and print session info
from a session file.

The tool operates in one of two modes:
1. Configure/ modify the session attributes.
2. Print the session information. This is the default behavior.

# OPTIONS

  * **\--enable-continuesession**:

    Enable continueSession in the session-attributes.

  * **\--disable-continuesession**

    Disable continuesession in the session-attributes.

  * **\--enable-auditexclusive**

    Enable auditexclusive in the session-attributes.

  * **\--disable-auditexclusive**

    Disable auditexclusive in the session-attributes.

  * **\--enable-auditreset**

    Enable  auditreset in the session-attributes.

  * **\--disable-auditreset**

    Disable auditreset in the session-attributes.

  * **\--enable-decrypt**

    Enable  decrypt in the session-attributes.

  * **\--disable-decrypt**

    Disable decrypt in the session-attributes.

  * **\--enable-encrypt**

    Enable  encrypt in the session-attributes.

  * **\--disable-encrypt**

    Disable encrypt in the session-attributes.

  * **\--enable-audit**

    Enable  audit in the session-attributes.

  * **\--disable-audit**

    Disable audit in the session-attributes.

* **ARGUMENT** the session context file.

## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Start a bounded & salted session, disable continuesession and display session

```bash

tpm2 createprimary -c prim.ctx
tpm2 startauthsession -S session.ctx --policy-session -c prim.ctx

### Session info before changing attributes
tpm2 sessionconfig session.ctx

### Session info after changing attributes
tpm2 sessionconfig --disable-continuesession
tpm2 sessionconfig session.ctx

```

[returns](common/returns.md)

[footer](common/footer.md)
