% tpm2_policyduplicationselect(1) tpm2-tools | General Commands Manual
%
% MARCH 2018

# NAME

**tpm2_policyduplicationselect**(1) - Restricts duplication to specific New Parent.

# SYNOPSIS

**tpm2_policyduplicationselect** [*OPTIONS*] 

# DESCRIPTION

**tpm2_policyduplicationselect**(1) Restricts duplication to specific New Parent.

# OPTIONS

  * **-S**, **--session**=_SESSION_FILE_:

    The policy session file generated via the **-S** option to
    **tpm2_startauthsession**(1).

  * **-n**, **--obj-name**=_OBJ\_NAME\_FILE_:

    Input NAME file of the object to be duplicated.

  * **-p**, **--new-parent-name**=_NP\_NAME\_FILE_:

    Input NAME file of the new parent.

  * **-o**, **--policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

  * **-i**, **--is-include-object**:

    If exists, the objectName will be included in the value in policySession->PolicyDigest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

* this command usually coorperates with tpm2_duplicate, so, firstly refering to the man page of tpm2_duplicate
is recommended. 

* Note: this command will set policySession->commandCode to TPM_CC_Duplicate, which enables DUP role of 
the policy.

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
