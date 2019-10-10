% tss2_encrypt(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_encrypt**(1) - encrypts data

# SYNOPSIS

**tss2_encrypt** [*OPTIONS*]

# DESCRIPTION

**tss2_encrypt**(1) - This command encrypts the provided data for a target key.

If keypath is an asymmetric key and a plaintext with size >= TPM2_MAX_SYM_SIZE is provided, Fapi_Encrypt() will bulk-encrypt the plaintext with an intermediate symmetric key and then “seal” this intermediate symmetric key with keyPath as a KEYEDHASH TPM object. This keyPath may refer to the local TPM or to a public key of a remote TPM where the KEYEDHASH can be imported. The decrypt operation performs a TPM2_Unseal. ciphertext output contains a reference to the decryption key, the sealed symmetric key (if any), the policy instance, and the encrypted plaintext.

If plaintext has a size <= TPM2_MAX_SYM_SIZE the plaintext is sealed directly for keyPath.

If encrypting for the local TPM (if keyPath is not from the external hierarchy), a storage key (symmetric or asymmetric) is required as keyPath (aka parent key) and the data intermediate symmetric key is created using TPM2_Create() as a KEYEDHASH object.

If encrypting for a remote TPM, an asymmetric storage key is required as keyPath (aka parent key), and the data/intermediate symmetric key is encrypted such that it can be used in a TPM2_Import operation. The format of the cipherText is described in the FAPI specification.


# OPTIONS

These are the available options:

  * **-p**, **\--keyPath**:

    Identifies the encryption key. MUST NOT be NULL.

  * **-f**, **\--force**:

    Force overwriting the output file.

  * **-P**, **\--policyPath**:

    Identifies the policy to be associated with the sealed data. MAY be NULL. If NULL then the sealed data will have no policy.

  * **-i**, **\--plainText**:

    The data to be encrypted. MUST NOT be NULL.

  * **-o**, **\--cipherText**:

    Returns the JSON-encoded ciphertext. MUST NOT be NULL.

[common tss2 options](common/tss2-options.md)

# EXAMPLE

  tss2_encrypt --keyPath HS/SRK/myRSACrypt --plainText plaintext.file --cipherText encrypted.file

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
