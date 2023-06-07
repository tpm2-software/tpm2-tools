# PCR Bank Specifiers

PCR Bank Selection lists follow the below specification:

```
<BANK>:<PCR>[,<PCR>] or <BANK>:all
```

multiple banks may be separated by '+'.

For example:

```
sha1:3,4+sha256:all
```
will select PCRs 3 and 4 from the SHA1 bank and PCRs 0 to 23
from the SHA256 bank.

Certain commands support specifying forward sealing values as well:

```
sha1:0,1=da39a3ee5e6b4b0d3255bfef95601890afd80709,2
```
This will select the current values for PCRs 0 and 2, but use the specified
value for PCR 1.  Digest lengths must match the bank size.  An optional 0x
prefix will be stripped off.

## Note
PCR Selections allow for up to 5 hash to pcr selection mappings.
This is a limitation in design in the single call to the tpm to
get the pcr values.
