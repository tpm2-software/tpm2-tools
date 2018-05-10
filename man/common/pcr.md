# PCR Bank Specifiers

PCR Bank Selection lists follow the below specification:

```
<BANK>:<PCR>[,<PCR>]
```

multiple banks may be separated by '+'.

For example:

```
sha1:3,4+sha256:5,6
```
will select PCRs 3 and 4 from the SHA1 bank and PCRs 5 and 6
from the SHA256 bank.

## Note
PCR Selections allow for up to 5 hash to pcr selection mappings.
This is a limitation in design in the single call to the tpm to
get the pcr values.
