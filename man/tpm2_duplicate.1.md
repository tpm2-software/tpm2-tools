% tpm2_duplicate(1) tpm2-tools | General Commands Manual

# NAME

tpm2_duplicate(1) -  Duplicates a loaded object so that it may be used in a
different hierarchy.

# SYNOPSIS

**tpm2_duplicate** [*OPTIONS*]

# DESCRIPTION

**tpm2_duplicate**(1) - This tool duplicates a loaded object so that it may be
used in a different hierarchy. The new parent key for the duplicate may be on
the same or different TPM or TPM_RH_NULL.

# OPTIONS

These options control the key importation process:

  * **-G**, **\--wrapper-algorithm**=_ALGORITHM_:

    The symmetric algorithm to be used for the inner wrapper. Supports:
    * aes - AES 128 in CFB mode.
    * null - none

  * **-i**, **\--encryptionkey-in**=_FILE_:

    Specifies the filename of the symmetric key (128 bit data) to be used for
    the inner wrapper. Valid only when specified symmetric algorithm is not null

  * **-o**, **\--encryptionkey-out**=_FILE_:

    Specifies the filename to store the symmetric key (128 bit data) that was
    used for the inner wrapper. Valid only when specified symmetric algorithm is
    not null and \--input-key-file is not specified. The TPM generates the key
    in this case.

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent key object.

  * **-r**, **\--private**=_FILE_:

    Specifies the file path to save the private portion of the duplicated object.
    [protection details](common/protection-details.md)

  * **-s**, **\--encrypted-seed**=_FILE_:

    The file to save the encrypted seed of the duplicated object.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the key, optional.

  * **-c**, **\--key-context**=_OBJECT_:

    The object to be duplicated.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

To duplicate a key, one needs the key to duplicate, created with a policy that \
allows duplication and a new parent:
```bash
tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctxt
tpm2_create -C primary.ctxt -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin"

tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctxt

tpm2_startauthsession \--policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate
tpm2_duplicate -C new_parent.ctxt -c key.ctxt -G null -p "session:session.dat" \
-r duprv.bin -s seed.dat
tpm2_flushcontext session.dat
```

As an end-to-end example, the following will transfer an RSA key generated on 
`TPM-A` to `TPM-B`

## On TPM-B

Create a parent object that will be used to wrap/transfer the key.
```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_create  -C primary.ctx -g sha256 -G rsa \
-r new_parent.prv  -u new_parent.pub \
-a "restricted|sensitivedataorigin|decrypt|userwithauth"
```

Copy `new_parent.pub` to `TPM-A`.

## On TPM-A

Create root object and auth policy allows duplication only

```
tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx

tpm2_startauthsession -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate

tpm2_flushcontext session.dat

rm session.dat
```

Generate an RSA keypair on TPM-A that will be duplicated 
(note the passphrase is 'foo')

```
tpm2_create -C primary.ctx -g sha256 -G rsa -p foo -r key.prv \
-u key.pub  -L dpolicy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign"

tpm2_load -C primary.ctx -r key.prv -u key.pub -c key.ctx

tpm2_readpublic -c key.ctx -o dup.pub
````

Test sign and encryption locally (so we can compare later that the same key 
was transferred).

```
echo "meet me at.." >file.txt
tpm2_rsaencrypt -c key.ctx  -o data.encrypted file.txt
tpm2_sign -c key.ctx -g sha256 -f plain -p foo -o sign.raw file.txt
```

Compare the signature hash (we will use this later to confirm the key was 
transferred to TPM-B):

```
sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

Start an auth session and policy command to allow duplication
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the new_parent.pub file transferred from `TPM-B`
```
tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctx
```

Start the duplication
```
tpm2_duplicate -C new_parent.ctx -c key.ctx -G null  \
-p "session:session.dat" -r dup.dpriv -s dup.seed
```

Copy the following files to TPM-B:
* dup.pub
* dup.dpriv
* dup.seed
* (optionally data.encrypted just to test decryption)

## On TPM-B

Start an auth,policy session
```
tpm2_startauthsession --policy-session -S session.dat

tpm2_policycommandcode -S session.dat -L dpolicy.dat TPM2_CC_Duplicate
```

Load the context we used to transfer
```
tpm2_flushcontext --transient-object

tpm2_load -C primary.ctx -u new_parent.pub -r new_parent.prv -c new_parent.ctx
```

Import the duplicated context against the parent we used
```
tpm2_import -C new_parent.ctx -u dup.pub -i dup.dpriv \
-r dup.prv -s dup.seed -L dpolicy.dat
```

Load the duplicated key context 
```
tpm2_flushcontext --transient-object

tpm2_load -C new_parent.ctx -u dup.pub -r dup.prv -c dup.ctx
```

Test the imported key matches

* Sign

```bash
echo "meet me at.." >file.txt

tpm2_sign -c dup.ctx -g sha256 -o sig.rss -p foo file.txt

dd if=sig.rss of=sign.raw bs=1 skip=6 count=256
```

Compare the signature file hash:

```bash
$ sha256sum sign.raw

a1b4e3fbaa29e6e46d95cff498150b6b8e7d9fd21182622e8f5a3ddde257879e
```

* Decryption

```
tpm2_flushcontext --transient-object

tpm2_rsadecrypt -p foo -c dup.ctx -o data.ptext data.encrypted

# cat data.ptext 
meet me at..
```


[returns](common/returns.md)

[footer](common/footer.md)
