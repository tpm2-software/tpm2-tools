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

  * **-C**, **\--hierarchy**=_AUTH\_HANDLE_:

    Specifies the handle used to authorize. Defaults to the "platform" hierarchy.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **`<num>`** where a raw number can be used.

  * **-P**, **\--hierarchy-auth**=_HIERARCHY\_\_AUTH\_VALUE_:

    Specifies the authorization value for the hierarchy. Authorization values
    should follow the "authorization formatting standards", see section
    "Authorization Formatting".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

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
