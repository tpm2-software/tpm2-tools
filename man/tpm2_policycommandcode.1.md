% tpm2_policycommandcode(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_policycommandcode**(1) - Restrict TPM object authorization to specific
TPM commands or operations.

# SYNOPSIS

**tpm2_policycommandcode** [*OPTIONS*] _COMMAND\_CODE_

# DESCRIPTION

**tpm2_policycommandcode**(1) - Restricts TPM object authorization to specific
TPM commands or operations. Useful when you want to allow only specific commands
with the TPM object. As an argument it takes the _COMMAND\_CODE_ as an integer
or friendly string value. Friendly string to COMMAND CODE mapping can be found
in section *COMMAND CODE MAPPINGS*.

Requires support for extended sessions with resource manager.

# OPTIONS

  * **-S**, **\--session**=_SESSION\_FILE_:

    A session file from **tpm2_startauthsession**(1)'s **-S** option.

  * **-o**, **\--out-policy-file**=_POLICY\_FILE_:

    File to save the policy digest.

[common options](common/options.md)

[common tcti options](common/tcti.md)

<!-- Generated Via (requires minor hand tweaks still)
IFS=$'\n'
for c in `grep TPM2_CC_ ./include/tss2/tss2_tpm2_types.h`; do
  n=`echo $c | awk {'print $4'} | sed s/\)// | sed s/0x00000/0x/`
  p=`echo $c |awk {'print$2'} | cut -d'_' -f3- | sed s/_//g | tr '[:upper:]' '[:lower:]'`
  echo "  -$p: $n"
done;
-->

# COMM AND CODE MAPPINGS

The friendly strings below can be used en lieu of the raw integer values.

  - nvundefinespacespecial: 0x11f
  - evictcontrol: 0x120
  - hierarchycontrol: 0x121
  - nvundefinespace: 0x122
  - changeeps: 0x124
  - changepps: 0x125
  - clear: 0x126
  - clearcontrol: 0x127
  - clockset: 0x128
  - hierarchychangeauth: 0x129
  - nvdefinespace: 0x12a
  - pcrallocate: 0x12b
  - pcrsetauthpolicy: 0x12c
  - ppcommands: 0x12d
  - setprimarypolicy: 0x12e
  - fieldupgradestart: 0x12f
  - clockrateadjust: 0x130
  - createprimary: 0x131
  - nvglobalwritelock: 0x132
  - getcommandauditdigest: 0x133
  - nvincrement: 0x134
  - nvsetbits: 0x135
  - nvextend: 0x136
  - nvwrite: 0x137
  - nvwritelock: 0x138
  - dictionaryattacklockreset: 0x139
  - dictionaryattackparameters: 0x13a
  - nvchangeauth: 0x13b
  - pcrevent: 0x13c
  - pcrreset: 0x13d
  - sequencecomplete: 0x13e
  - setalgorithmset: 0x13f
  - setcommandcodeauditstatus: 0x140
  - fieldupgradedata: 0x141
  - incrementalselftest: 0x142
  - selftest: 0x143
  - startup: 0x144
  - shutdown: 0x145
  - stirrandom: 0x146
  - activatecredential: 0x147
  - certify: 0x148
  - policynv: 0x149
  - certifycreation: 0x14a
  - duplicate: 0x14b
  - gettime: 0x14c
  - getsessionauditdigest: 0x14d
  - nvread: 0x14e
  - nvreadlock: 0x14f
  - objectchangeauth: 0x150
  - policysecret: 0x151
  - rewrap: 0x152
  - create: 0x153
  - ecdhzgen: 0x154
  - hmac: 0x155
  - import: 0x156
  - load: 0x157
  - quote: 0x158
  - rsadecrypt: 0x159
  - hmacstart: 0x15b
  - sequenceupdate: 0x15c
  - sign: 0x15d
  - unseal: 0x15e
  - policysigned: 0x160
  - contextload: 0x161
  - contextsave: 0x162
  - ecdhkeygen: 0x163
  - encryptdecrypt: 0x164
  - flushcontext: 0x165
  - loadexternal: 0x167
  - makecredential: 0x168
  - nvreadpublic: 0x169
  - policyauthorize: 0x16a
  - policyauthvalue: 0x16b
  - policycommandcode: 0x16c
  - policycountertimer: 0x16d
  - policycphash: 0x16e
  - policylocality: 0x16f
  - policynamehash: 0x170
  - policyor: 0x171
  - policyticket: 0x172
  - readpublic: 0x173
  - rsaencrypt: 0x174
  - startauthsession: 0x176
  - verifysignature: 0x177
  - eccparameters: 0x178
  - firmwareread: 0x179
  - getcapability: 0x17a
  - getrandom: 0x17b
  - gettestresult: 0x17c
  - hash: 0x17d
  - pcrread: 0x17e
  - policypcr: 0x17f
  - policyrestart: 0x180
  - readclock: 0x181
  - pcrextend: 0x182
  - pcrsetauthvalue: 0x183
  - nvcertify: 0x184
  - eventsequencecomplete: 0x185
  - hashsequencestart: 0x186
  - policyphysicalpresence: 0x187
  - policyduplicationselect: 0x188
  - policygetdigest: 0x189
  - testparms: 0x18a
  - commit: 0x18b
  - policypassword: 0x18c
  - zgen2phase: 0x18d
  - ecephemeral: 0x18e
  - policynvwritten: 0x18f
  - policytemplate: 0x190
  - createloaded: 0x191
  - policyauthorizenv: 0x192
  - encryptdecrypt2: 0x193
  - acgetcapability: 0x194
  - acsend: 0x195
  - policyacsendselect: 0x196
  - vendortcgtest: 0x20000000


# EXAMPLES

Start a *policy* session and extend it with a specific command like unseal.
Attempts to perform other operations would fail.

## Create an unseal-only policy
```
TPM_CC_UNSEAL=0x15E

tpm2_startauthsession -S session.dat

tpm2_policycommandcode -S session.dat -o policy.dat $TPM_CC_UNSEAL

tpm2_flushcontext -S session.dat
```

## Create the object with unseal-only auth policy
```
tpm2_createprimary -a o -o prim.ctx

tpm2_create -C prim.ctx -u sealkey.pub -r sealkey.priv -L policy.dat \
  -i- <<< "SEALED-SECRET"
```

## Try unseal operation
```
tpm2_load -C prim.ctx -u sealkey.pub -r sealkey.priv -n sealkey.name \
  -o sealkey.ctx

tpm2_startauthsession \--policy-session -S session.dat

tpm2_policycommandcode -S session.dat -o policy.dat $TPM_CC_UNSEAL

tpm2_unseal -p session:session.dat -c sealkey.ctx

tpm2_flushcontext -S session.dat
```

## Try any other operation
```
echo "Encrypt Me" > plain.txt

tpm2_encryptdecrypt -i plain.txt -o enc.txt -c sealkey.ctx

if [ $? != 0 ]; then
    echo "Expected that operations other than unsealing will fail"
fi
```

[returns](common/returns.md)

[footer](common/footer.md)
