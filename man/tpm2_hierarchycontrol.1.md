% tpm2_hierarchycontrol(1) tpm2-tools | General Commands Manual
%
% July 2019

# NAME

**tpm2_hierarchycontrol**(1) - Enable and disable use of a hierarchy and its
associated NV storage.

# SYNOPSIS

**tpm2_hierarchycontrol** [*OPTIONS*] _VARIABLE_ _OPERATION_

# DESCRIPTION

**tpm2_hierarchycontrol**(1) - Allows user change phEnable, phEnableNV, shEnable
and ehEnable when the proper authorization is provided. Authorization should be
one out of owner hierarchy auth, endorsement hierarchy auth and platform
hierarchy auth. **As an argument the tool takes the _VARIABLE_ as
_TPMA\_STARTUP_CLEAR_ bit and \_OPERATION\_ as string clear|set to clear or set
the _VARIABLE_ bit.**

Note: If password option is missing, assume NULL.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    Specifies the handle used to authorize. Defaults to the "platform" hierarchy.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-P**, **\--hierarchy-auth**=_AUTH_:

    Specifies the authorization value for the hierarchy.

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

## Set phEnableNV with platform hierarchy and its authorization
```bash
tpm2_hierarchycontrol -C p phEnableNV set -P pass
```

## clear phEnableNV with platform hierarchy
```bash
tpm2_hierarchycontrol -C p phEnableNV clear
```

## Set shEnable with platform hierarchy
```bash
tpm2_hierarchycontrol -C p shEnable set
```

## Set shEnable with owner hierarchy
```bash
tpm2_hierarchycontrol -C o shEnable set
```

## Check current TPMA_STARTUP_CLEAR Bits
```bash
tpm2_getcap properties-variable
```

[returns](common/returns.md)

[footer](common/footer.md)
