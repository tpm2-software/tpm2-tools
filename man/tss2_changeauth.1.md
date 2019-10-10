% tss2_changeauth(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_changeauth**(1) - This command changes the authorization data of an entity referred to by the path.

The authValue is a UTF-8 password. If the length of the password is larger than the digest size of the entity's nameAlg (which is stored internally as part of its meta data) then the FAPI should hash the password, in accordance with the TPM specification, part 1 rev 138, section 19.6.4.3 "Authorization Size Convention."

# SYNOPSIS

**tss2_changeauth** [*OPTIONS*]

# DESCRIPTION

**tss2_changeauth**(1) -

# OPTIONS

These are the available options:

  * **-a**, **\--authValue**:

    The new 0-terminated password. MAY be NULL. If NULL then the password is set to the empty string.

  * **-p**, **\--entityPath**:

    The path identifying the entity to modify. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLES

## Change a password for an entity HS/SRK/myRSACryptKey to M1
```
tss2_changeauth --entityPath HS/SRK/myRSACryptKey --authValue M1
```

## Change a password for an entity HS/SRK/myRSACryptKey and ask the user to enter the password with disabled ecoh.
```
tss2_changeauth --entityPath HS/SRK/myRSACryptKey --authValue
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
