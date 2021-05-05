% tpm2(1) tpm2-tools | General Commands Manual

# NAME

**tpm2**(1) - A single small executable that combines the various tpm2-tools
much like a BusyBox that provides a fairly complete environment for any small or
embedded system.

# SYNOPSIS

**tpm2** [*OPTIONS*] [*ARGUMENTS*]

# DESCRIPTION

**tpm2**(1) - To ease installation of tpm2-tools in initrd or embedded systems
where size-optimization and limited resources are important, it is convenient to
have a single executable that can dispatch the various TPM2 functionalities
specified by the argument which is one of the available tool names.

The options and arguments that follow are either the **common options** or those
specific to the **tool name**.

It is important to note that individual tools with prefix **tpm2_** can still be
invoked, however, they are now soft-linked to this **tpm2** executable. And so
unlike BusyBox, full functionality of the individual tools is available in the
executable. For example: **tpm2_getrandom 8** can alternatively be specified as
**tpm2 getrandom 8**.


# ARGUMENTS

List of possible tool names. NOTE: Specify only one of these. Look at examples.

**certifyX509certutil**

**checkquote**

**eventlog**

**print**

**rc_decode**

**activatecredential**

**certify**

**changeauth**

**changeeps**

**changepps**

**clear**

**clearcontrol**

**clockrateadjust**

**create**

**createak**

**createek**

**createpolicy**

**setprimarypolicy**

**createprimary**

**dictionarylockout**

**duplicate**

**getcap**

**gettestresult**

**encryptdecrypt**

**evictcontrol**

**flushcontext**

**getekcertificate**

**getrandom**

**gettime**

**hash**

**hierarchycontrol**

**hmac**

**import**

**incrementalselftest**

**load**

**loadexternal**

**makecredential**

**nvdefine**

**nvextend**

**nvincrement**

**nvreadpublic**

**nvread**

**nvreadlock**

**nvundefine**

**nvwrite**

**nvwritelock**

**nvsetbits**

**pcrallocate**

**pcrevent**

**pcrextend**

**pcrread**

**pcrreset**

**policypcr**

**policyauthorize**

**policyauthorizenv**

**policynv**

**policycountertimer**

**policyor**

**policynamehash**

**policytemplate**

**policycphash**

**policypassword**

**policysigned**

**policyticket**

**policyauthvalue**

**policysecret**

**policyrestart**

**policycommandcode**

**policynvwritten**

**policyduplicationselect**

**policylocality**

**quote**

**readclock**

**readpublic**

**rsadecrypt**

**rsaencrypt**

**send**

**selftest**

**sessionconfig**

**setclock**

**shutdown**

**sign**

**certifycreation**

**nvcertify**

**startauthsession**

**startup**

**stirrandom**

**testparms**

**unseal**

**verifysignature**

**setcommandauditstatus**

**getcommandauditdigest**

**getsessionauditdigest**

**geteccparameters**

**ecephemeral**

**commit**

**ecdhkeygen**

**ecdhzgen**

**zgen2phase**


## References

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

## Get 8 rand bytes from the TPM
```bash
tpm2 getrandom 8 | xxd -p
```

## Send a TPM Startup Command with flags TPM2\_SU\_CLEAR
```bash
tpm2 startup -c
```

[returns](common/returns.md)

[footer](common/footer.md)
