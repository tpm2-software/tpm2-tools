% tpm2_makecredential(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_makecredential**(1) - Generate the encrypted-user-chosen-data and the
wrapped-secret-data-encryption-key for the privacy-sensitive credentialing
process of a TPM object.

# SYNOPSIS

**tpm2_makecredential** [*OPTIONS*]

# DESCRIPTION

**tpm2_makecredential**(1) - The TPM supports a privacy preserving protocol for
distributing credentials for keys on a TPM. The process guarantees that the
credentialed-TPM-object(AIK) is loaded on the same TPM as a well-known
public-key-object(EK) without knowledge of the specific public properties of the
credentialed-TPM-object(AIK). The privacy is guaranteed due to the fact that
only the name of the credentialed-TPM-object(AIK) is shared and not the
credentialed-TPM-object's public key itself.

Make-credential is the first step in this process where in after receiving the
public-key-object(EK) public key of the TPM and the name of the
credentialed-TPM-object(AIK), an encrypted-user-chosen-data is generated and the
secret-data-encryption-key is generated and wrapped using cryptographic
processes specific to credential activation that guarantees that the
credentialed-TPM-object(AIK) is loaded on the TPM with the well-known
public-key-object(EK).

**tpm2_makecredential** can be used to generate the encrypted-user-chosen-data
and the wrapped secret-data-encryption-key without a TPM by using the **none**
TCTI option.

# OPTIONS

  * **-e**, **\--encryption-key**=_FILE_:

    **DEPRECATED**, use **-u** or **--public** instead.

  * **-u**, **\--public**=_FILE_:

    A TPM public key which was used to wrap the seed.
    NOTE: This option is same as **-e** and is added to make it similar with
    other tools specifying the public key. The old option is retained for
    backwards compatibility.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The key algorithm associated with TPM public key. Specify either RSA/ ECC.
    When this option is used, input public key is expected to be in PEM format
    and the default TCG EK template is used for the key properties.

  * **-s**, **\--secret**=_FILE_ or _STDIN_:

    The secret which will be protected by the key derived from the random seed. It can be specified as a file or passed from stdin.

  * **-n**, **\--name**=_FILE_:

    The name of the key for which certificate is to be created.

  * **-o**, **\--credential-blob**=_FILE_:

    The output file path, recording the encrypted-user-chosen-data and the
    wrapped secret-data-encryption-key.

[common options](common/options.md)

[common tcti options](common/tcti.md)

# EXAMPLES

```bash
tpm2 createek -Q -c 0x81010009 -G rsa -u ek.pub

tpm2 createak -C 0x81010009 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub \
-n ak.name -p akpass> ak.out

file_size=`ls -l ak.name | awk {'print $5'}`
loaded_key_name=`cat ak.name | xxd -p -c $file_size`

tpm2 readpublic -c 0x81010009 -o ek.pem -f pem -Q

echo "12345678" | tpm2 makecredential -Q -u ek.pem -s - -n $loaded_key_name \
-o mkcred.out -G rsa
```

[returns](common/returns.md)

[footer](common/footer.md)
