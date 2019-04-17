% tpm2_policyduplicationselect(1) tpm2-tools | General Commands Manual
%
% MARCH 2018

# NAME

**tpm2_policyduplicationselect**(1) - Restricts duplication to specific new parent.

# SYNOPSIS

**tpm2_policyduplicationselect** [*OPTIONS*]

# DESCRIPTION

**tpm2_policyduplicationselect**(1) - Restricts duplication to specific new parent.

# OPTIONS

  * **-S**, **--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-n**, **--object-name**=_OBJ\_NAME\_FILE_:

    Input name file of the object to be duplicated.

  * **-N**, **--new-parent-name**=_NP\_NAME\_FILE_:

    Input name file of the new parent.

  * **-o**, **--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

  * **--include-object-if-exists**:

    If exists, the object name will be included in the value in policy digest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# NOTES

* This command usually coorperates with **tpm2_duplicate**(1), so, firstly refering to the man page of **tpm2_duplicate**(1)
is recommended.

* This command will set the policy session's command code to **TPM_CC_Duplicate** which enables duplication role of
the policy.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
